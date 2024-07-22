#ifndef HEXANE_CORELIB_MESSAGE_HPP
#define HEXANE_CORELIB_MESSAGE_HPP
#include "core/monolith.hpp"
#include "core/corelib.hpp"

namespace Message {
    FUNCTION BOOL PeekPID(PSTREAM Stream);
    FUNCTION VOID CommandDispatch (PSTREAM Inbound);
    FUNCTION VOID AddMessage(PSTREAM Outbound);
    FUNCTION VOID ClearQueue(VOID);
    FUNCTION VOID QueueSegments(PBYTE Buffer, ULONG Length);
    FUNCTION VOID OutboundQueue(PSTREAM Outbound);
    FUNCTION VOID MessageTransmit(VOID);
}
#endif //HEXANE_CORELIB_MESSAGE_HPP

