#include <include/process.hpp>
namespace Process {

    DWORD GetProcessIdByName (LPSTR Process) {
        HEXANE

        HANDLE hSnap 			= { };
        PROCESSENTRY32 entry 	= { };
        entry.dwSize 			= sizeof(PROCESSENTRY32);

        if (!(hSnap = Ctx->win32.CreateToolhelp32Snapshot(0x02, 0))) {
            return_defer(ERROR_INVALID_HANDLE);
        }

        if (Ctx->win32.Process32First(hSnap, &entry) == TRUE) {
            while (Ctx->win32.Process32Next(hSnap, &entry) == TRUE) {
                if (x_strcmp(Process, entry.szExeFile) == 0) {

                    Ctx->Nt.NtClose(hSnap);
                    return entry.th32ProcessID;
                }
            }
        }
        defer:
        if (hSnap) {
            Ctx->Nt.NtClose(hSnap);
        }

        return 0;
    }
}
