#ifndef HEXANE_CORELIB_DISPATCH_HPP
#define HEXANE_CORELIB_DISPATCH_HPP

#include <core/corelib.hpp>

namespace Dispatcher {
    FUNCTION DWORD PeekPeerId(const _stream *stream);
    FUNCTION VOID AddMessage(_stream *out);
    FUNCTION VOID RemoveMessage(const _stream *target);
    FUNCTION VOID OutboundQueue(_stream *out);
    FUNCTION VOID QueueSegments(uint8_t *buffer, uint32_t length);
    FUNCTION VOID PrepareEgressMessage(_stream *out);
    FUNCTION VOID PrepareIngressMessage(_stream *in);
    FUNCTION VOID MessageTransmit();
    FUNCTION VOID CommandDispatch (const _stream *in);
}
#endif //HEXANE_CORELIB_DISPATCH_HPP

