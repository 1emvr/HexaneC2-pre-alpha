#ifndef VEH_HPP
#define VEH_HPP
#include <core/corelib.hpp>

namespace Veh {
	FUNCTION UINT_PTR VehGetFirstHandler(const wchar_t *mod_name, const char *signature, const char *mask);
	FUNCTION LONG WINAPI Debugger(EXCEPTION_POINTERS *exception);
}
#endif //VEH_HPP
