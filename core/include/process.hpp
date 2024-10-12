#ifndef HEXANE_CORELIB_PROCESS_HPP
#define HEXANE_CORELIB_PROCESS_HPP
#include <core/corelib.hpp>

namespace Process {
	ULONG
	FUNCTION
		GetProcessIdByName(CONST CHAR *name);

	HANDLE
	FUNCTION
		OpenParentProcess(CONST CHAR *name);

	VOID
	FUNCTION
		CreateUserProcess(EXECUTABLE *image, CONST CHAR *path);

	VOID
	FUNCTION
		CloseUserProcess(EXECUTABLE *image);

	NTSTATUS
	FUNCTION
		NtOpenProcess(VOID **pp_process, UINT32 access, UINT32 pid);
}
#endif //HEXANE_CORELIB_PROCESS_HPP
