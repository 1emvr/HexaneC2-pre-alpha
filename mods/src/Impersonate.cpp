#include <core/include/monolith.hpp>
#include <core/include/cruntime.hpp>
#include <core/include/memory.hpp>

using namespace Memory;

NTSTATUS ImpersonateProcess(LPCWSTR lpszCmd, LPWSTR lpszCmdLine, DWORD pid) {

	HANDLE hProcess 	= { };
	HANDLE hToken 		= { };
	HANDLE hDuplicate 	= { };

	STARTUPINFOW sui 		= { };
	PROCESS_INFORMATION pi 	= { };

	TOKEN_PRIVILEGES tp 	= { };
	LUID luid 				= { };

	SIZE_T piSize = sizeof(pi);
	SIZE_T suiSize = sizeof(sui);

	x_memset(&sui, 0, suiSize);
	x_memset(&pi, 0, piSize);

	if (
		!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) ||
		!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
		goto defer;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (
		!(hProcess= OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid)) ||
		!OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken) ||
		!ImpersonateLoggedOnUser(hToken)) {
		goto defer;
	}

	DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &hDuplicate);
	CreateProcessWithTokenW(hDuplicate, LOGON_WITH_PROFILE, lpszCmd, nullptr, 0, nullptr, nullptr, &sui, &pi);

defer:
	return GetLastError();
}
