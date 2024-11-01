#ifndef HEXANE_CORELIB_BASE_HPP
#define HEXANE_CORELIB_BASE_HPP
#include <core/corelib.hpp>

EXTERN_C
VOID
FUNCTION
    Entrypoint();

Main {
    VOID
    FUNCTION
        MainRoutine();

    BOOL
    FUNCTION
        EnumSystem();

    BOOL
    FUNCTION
        ResolveApi();

    BOOL
    FUNCTION
        ReadConfig();
}
#endif //HEXANE_CORELIB_BASE_HPP
