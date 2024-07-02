#ifndef HEXANE_MESSAGE_HPP
#define HEXANE_MESSAGE_HPP
#include <include/monolith.hpp>
#include <include/network.hpp>

namespace Messages {
    FUNCTION BOOL PeekPID(PSTREAM Stream);
    FUNCTION VOID CommandDispatch (PSTREAM Inbound);
    FUNCTION VOID AddMessage(PSTREAM Outbound);
    FUNCTION VOID ClearQueue(VOID);
    FUNCTION VOID QueueSegments(PBYTE Buffer, DWORD Length);
    FUNCTION VOID OutboundQueue(PSTREAM Outbound);
    FUNCTION VOID MessageTransmit(VOID);
}
#endif //HEXANE_MESSAGE_HPP

