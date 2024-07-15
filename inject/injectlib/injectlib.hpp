#ifndef _HEXANE_INJECTLIB_CONFIG_HPP
#define _HEXANE_INJECTLIB_CONFIG_HPP
#include <monolith.hpp>
#include <core/corelib/corelib.hpp>
#include <inject/injectlib/resource.hpp>

struct THREADLESS {
    ABUFFER Parent = { };
    ABUFFER Module = { };
    ABUFFER Export = { };
    ABUFFER Loader = { };
    ABUFFER Opcode = { };
};

EXTERN_C VOID Execute();
DLL_EXPORT FUNCTION VOID Entrypoint(HMODULE Base);

namespace Injection {
    VOID Threadless(HMODULE Base);

}
#endif //_HEXANE_INJECTLIB_CONFIG_HPP
