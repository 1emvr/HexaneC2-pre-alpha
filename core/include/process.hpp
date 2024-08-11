#ifndef HEXANE_CORELIB_PROCESS_HPP
#define HEXANE_CORELIB_PROCESS_HPP

#include <core/corelib.hpp>
namespace Process {

	FUNCTION ULONG GetProcessIdByName(char *name);
	FUNCTION NTSTATUS NtOpenProcess(void **pp_process, uint32_t access, uint32_t pid);
	FUNCTION VOID NtCloseUserProcess(_executable *process);
	FUNCTION VOID NtCreateUserProcess(_executable *process, const char *path);
	FUNCTION HANDLE OpenParentProcess(const char *parent);
}
#endif //HEXANE_CORELIB_PROCESS_HPP
