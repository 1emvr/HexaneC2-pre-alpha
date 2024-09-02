#ifndef HEXANE_CORELIB_OPSEC_HPP
#define HEXANE_CORELIB_OPSEC_HPP

#include <core/corelib.hpp>

namespace Opsec {
    FUNCTION BOOL CheckTime();
    FUNCTION BOOL CheckDebugger();
    FUNCTION BOOL CheckSandbox();
    FUNCTION BOOL CheckEnvironment();
    FUNCTION BOOL RuntimeChecks();
    FUNCTION BOOL ImageCheckArch(const _executable *const image);
    FUNCTION BOOL ImageCheckCompat(_executable exe, _executable proc);
    FUNCTION VOID SleepObf();
}

#endif //HEXANE_CORELIB_OPSEC_HPP
