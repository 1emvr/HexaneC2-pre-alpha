#ifndef _HEXANE_PROCESS_HPP
#define _HEXANE_PROCESS_HPP
#include <core/include/monolith.hpp>
#include <core/include/cruntime.hpp>

namespace Process {
	FUNCTION ULONG GetProcessIdByName(LPSTR proc);
	FUNCTION HANDLE NtOpenProcess(ULONG access, ULONG pid);
	FUNCTION VOID NtCloseUserProcess(PIMAGE proc);
	FUNCTION NTSTATUS NtCreateUserProcess(PIMAGE proc, LPCSTR path);
}
#endif
