#ifndef HEXANE_CORELIB_PROCESS_HPP
#define HEXANE_CORELIB_PROCESS_HPP
#include "core/corelib.hpp"

namespace Process {
	FUNCTION ULONG GetProcessIdByName(LPSTR proc);
	FUNCTION HANDLE NtOpenProcess(ULONG access, ULONG pid);
	FUNCTION VOID NtCloseUserProcess(PIMAGE proc);
	FUNCTION VOID NtCreateUserProcess(PIMAGE proc, LPCSTR path);
	FUNCTION HANDLE LdrGetParentHandle(PBYTE Parent);
}
#endif //HEXANE_CORELIB_PROCESS_HPP
