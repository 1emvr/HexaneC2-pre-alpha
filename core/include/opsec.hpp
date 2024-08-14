#ifndef HEXANE_CORELIB_OPSEC_HPP
#define HEXANE_CORELIB_OPSEC_HPP

#include <core/corelib.hpp>
namespace Opsec {

    FUNCTION BOOL CheckTime();
    FUNCTION VOID SeCheckDebugger();
    FUNCTION VOID SeCheckSandbox();
    FUNCTION VOID SeCheckEnvironment();
    FUNCTION VOID SeRuntimeCheck();
    FUNCTION BOOL SeImageCheckArch(const _executable *const image);
    FUNCTION BOOL SeImageCheckCompat(_executable exe, _executable proc);
    FUNCTION VOID SleepObf();
}

#endif //HEXANE_CORELIB_OPSEC_HPP
