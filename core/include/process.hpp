#ifndef HEXANE_CORELIB_PROCESS_HPP
#define HEXANE_CORELIB_PROCESS_HPP
#include <core/corelib.hpp>

namespace Process {
	FUNCTION ULONG GetProcessIdByName(const char *const name);
	FUNCTION HANDLE OpenParentProcess(const char *const name);
	FUNCTION NTSTATUS NtOpenProcess(void **pp_process, const uint32_t access, const uint32_t pid);
	FUNCTION VOID CloseUserProcess(_executable *const image);
	FUNCTION VOID CreateUserProcess(_executable *const image, const char *const path);
}
#endif //HEXANE_CORELIB_PROCESS_HPP
