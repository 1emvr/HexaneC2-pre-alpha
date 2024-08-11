#ifndef HEXANE_CORELIB_PROCESS_HPP
#define HEXANE_CORELIB_PROCESS_HPP
#include <core/corelib.hpp>

namespace Process {
	FUNCTION ULONG GetProcessIdByName(LPSTR proc);
	FUNCTION NTSTATUS NtOpenProcess(PHANDLE phProcess, ULONG access, ULONG pid);
	FUNCTION VOID NtCloseUserProcess(PIMAGE proc);
	FUNCTION VOID NtCreateUserProcess(PIMAGE proc, LPCSTR path);
	FUNCTION HANDLE OpenParentProcess(const char *parent);
}
#endif //HEXANE_CORELIB_PROCESS_HPP
