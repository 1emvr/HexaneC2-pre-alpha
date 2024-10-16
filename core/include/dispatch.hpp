#ifndef HEXANE_CORELIB_DISPATCH_HPP
#define HEXANE_CORELIB_DISPATCH_HPP
#include <core/corelib.hpp>

namespace Dispatcher {
    VOID
    FUNCTION
        MessageQueue(STREAM *msg);

    VOID
    FUNCTION
        PrepareEgress(STREAM *out);

    VOID
    FUNCTION
        AddMessage(STREAM *out);

    VOID
    FUNCTION
        RemoveMessage(STREAM *target);

    VOID
    FUNCTION
        QueueSegments(UINT8 *buffer, UINT32 length);

    VOID
    FUNCTION
        PrepareIngress(STREAM *in);

    VOID
    FUNCTION
        CommandDispatch(STREAM *in);

    BOOL
    FUNCTION
        DispatchRoutine();
}
#endif //HEXANE_CORELIB_DISPATCH_HPP

