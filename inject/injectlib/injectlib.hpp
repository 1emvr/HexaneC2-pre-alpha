#ifndef _HEXANE_INJECTLIB_CONFIG_HPP
#define _HEXANE_INJECTLIB_CONFIG_HPP
#include <core/monolith.hpp>
#include <core/corelib/corelib.hpp>
#include <inject/injectlib/resource.hpp>

EXTERN_C VOID Execute();
EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);
FUNCTION VOID RsrcLoader(HMODULE Base);

#endif //_HEXANE_INJECTLIB_CONFIG_HPP
