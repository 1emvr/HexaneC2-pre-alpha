#ifndef HEXANE_CORELIB_OPSEC_HPP
#define HEXANE_CORELIB_OPSEC_HPP
#include <core/monolith.hpp>
#include <core/corelib/corelib.hpp>

namespace Opsec {
    FUNCTION BOOL CheckTime();
    FUNCTION VOID SeCheckDebugger();
    FUNCTION VOID SeCheckSandbox();
    FUNCTION VOID SeCheckEnvironment();
    FUNCTION VOID SeRuntimeCheck();
    FUNCTION VOID SeImageCheck(PIMAGE img, PIMAGE proc);
    FUNCTION VOID SleepObf();
}

#endif //HEXANE_CORELIB_OPSEC_HPP
