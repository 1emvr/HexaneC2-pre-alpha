#ifndef HEXANE_CORELIB_MESSAGE_HPP
#define HEXANE_CORELIB_MESSAGE_HPP

#include <core/corelib.hpp>
namespace Dispatcher {

    FUNCTION BOOL PeekPID(_stream *stream);
    FUNCTION VOID CommandDispatch (_stream *in);
    FUNCTION VOID AddMessage(_stream *out);
    FUNCTION VOID ClearQueue(void);
    FUNCTION VOID QueueSegments(byte *buffer, uint32_t length);
    FUNCTION VOID OutboundQueue(_stream *out);
    FUNCTION VOID MessageTransmit(void);
}
#endif //HEXANE_CORELIB_MESSAGE_HPP

