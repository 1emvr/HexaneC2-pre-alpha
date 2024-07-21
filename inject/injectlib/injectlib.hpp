#ifndef _HEXANE_INJECTLIB_CONFIG_HPP
#define _HEXANE_INJECTLIB_CONFIG_HPP
#include <core/monolith.hpp>
#include <core/corelib/corelib.hpp>
#include <inject/injectlib/resource.hpp>

struct THREADLESS {
    A_BUFFER Parent = { };
    A_BUFFER Module = { };
    A_BUFFER Export = { };
    A_BUFFER Loader = { };
    A_BUFFER Opcode = { };
};

EXTERN_C VOID Execute();
DLL_EXPORT FUNCTION VOID Entrypoint(HMODULE Base);

namespace Injection {
    VOID Threadless(HMODULE Base);

}
#endif //_HEXANE_INJECTLIB_CONFIG_HPP
