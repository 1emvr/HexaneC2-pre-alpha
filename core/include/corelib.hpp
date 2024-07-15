#ifndef _HEXANE_CORELIB_CONFIG_HPP
#define _HEXANE_CORELIB_CONFIG_HPP
#include <monolith.hpp>

#define FUNCTION TXT_SECTION(core, B)
#define instance __CoreInstance

EXTERN_C ULONG __CoreInstance;
EXTERN_C LPVOID __Instance;

#define Ctx 			    __LocalInstance
#define InstanceOffset()    (U_PTR(&instance))
#define GLOBAL_OFFSET       (U_PTR(InstStart()) + InstanceOffset())
#define InstancePtr()	    ((HEXANE_CTX*) C_DREF(C_PTR(GLOBAL_OFFSET)))
#define HEXANE 		        HEXANE_CTX* __LocalInstance = InstancePtr();

#endif //_HEXANE_CORELIB_CONFIG_HPP
