#ifndef HEXANE_IMPLANT_THREADS_HPP
#define HEXANE_IMPLANT_THREADS_HPP
#include <core/corelib.hpp>

namespace Threads {
    FUNCTION HANDLE CreateUserThread(void* process, bool x64, void* entry, void* args, uint32_t* tid);
}

#endif //HEXANE_IMPLANT_THREADS_HPP
