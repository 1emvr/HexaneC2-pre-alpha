#ifndef HEXANE_CORELIB_OPSEC_HPP
#define HEXANE_CORELIB_OPSEC_HPP
#include <core/corelib.hpp>

namespace Opsec {
    BOOL
    FUNCTION
        CheckTime();

    BOOL
    FUNCTION
        RuntimeChecks();

    BOOL
    FUNCTION
        CheckDebugger();

    BOOL
    FUNCTION
        CheckSandbox();

    BOOL
    FUNCTION
        CheckEnvironment();

    BOOL
    FUNCTION
        ImageCheckArch(CONST EXECUTABLE *image);

    BOOL
    FUNCTION
        ImageCheckCompat(CONST EXECUTABLE *source, CONST EXECUTABLE *target);
}

#endif //HEXANE_CORELIB_OPSEC_HPP
