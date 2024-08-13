#ifndef HEXANE_CORELIB_BASE_HPP
#define HEXANE_CORELIB_BASE_HPP
#include <core/corelib.hpp>

EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);
_text(F) BYTE __config[sizeof(_hexane)] = {
    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
};

namespace Implant {
    FUNCTION VOID MainRoutine();
    FUNCTION VOID ReadConfig();
}
#endif //HEXANE_CORELIB_BASE_HPP