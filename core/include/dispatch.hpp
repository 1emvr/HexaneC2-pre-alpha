#ifndef HEXANE_CORELIB_DISPATCH_HPP
#define HEXANE_CORELIB_DISPATCH_HPP
#include <core/corelib.hpp>

namespace Dispatcher {
    FUNCTION DWORD PeekPeerId(const _stream *const stream);
    FUNCTION VOID AddMessage(_stream *const out);
    FUNCTION VOID RemoveMessage(const _stream *target);
    FUNCTION VOID MessageQueue(_stream *const msg);
    FUNCTION VOID QueueSegments(uint8_t *const buffer, uint32_t length);
    FUNCTION VOID PrepareEgress(_stream *out);
    FUNCTION VOID PrepareIngress(_stream *in);
    FUNCTION VOID DispatchRoutine();
    FUNCTION VOID CommandDispatch (const _stream *const in);
}
#endif //HEXANE_CORELIB_DISPATCH_HPP

