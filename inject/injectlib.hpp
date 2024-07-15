#ifndef _HEXANE_INJECTLIB_CONFIG_HPP
#define _HEXANE_INJECTLIB_CONFIG_HPP
#include <monolith.hpp>
#include <core/include/cipher.hpp>
#include <core/include/names.hpp>
#include <core/include/utils.hpp>
#include <core/include/memory.hpp>
#include <core/include/process.hpp>
#include <loader/resource.hpp>
#include <inject/config.hpp>

#define FUNCTION TXT_SECTION(inject, B)
#define instance __InjectInstance

EXTERN_C ULONG __InjectInstance;
EXTERN_C LPVOID __Instance;

#define Ctx 			    __LocalInstance
#define InstanceOffset()    (U_PTR(&instance))
#define GLOBAL_OFFSET       (U_PTR(InstStart()) + InstanceOffset())
#define InstancePtr()	    ((HEXANE_CTX*) C_DREF(C_PTR(GLOBAL_OFFSET)))
#define HEXANE 		        HEXANE_CTX* __LocalInstance = InstancePtr();

EXTERN_C VOID Execute();

namespace Injection {
    DLL_EXPORT EXTERN_C FUNCTION VOID Entrypoint(HMODULE Base);
    VOID Threadless(HMODULE Base);

}
#endif //_HEXANE_INJECTLIB_CONFIG_HPP
