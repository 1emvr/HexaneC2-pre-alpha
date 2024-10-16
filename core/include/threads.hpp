#ifndef HEXANE_IMPLANT_THREADS_HPP
#define HEXANE_IMPLANT_THREADS_HPP
#include <core/corelib.hpp>

namespace Threads {
    HANDLE
    FUNCTION
        CreateUserThread(VOID *process, VOID *entry, VOID *args, UINT32 *tid);
}

#endif //HEXANE_IMPLANT_THREADS_HPP
