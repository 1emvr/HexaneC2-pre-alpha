#include <core/include/modules.hpp>

using namespace Hash;
using namespace Opsec;
using namespace Utils;
using namespace Memory::Methods;

typedef BOOL(WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);
__attribute__((used, section(".rdata"))) uint8_t dot_dll[] = { 0x2a,0x00,0x2e,0x00,0x64,0x00,0x6c,0x00,0x6c,0x00,0x00 };
__attribute__((used, section(".rdata"))) uint8_t sys32[] = {
	0x43,0x00,0x3a,0x00,0x2f,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,
	0x77,0x00,0x73,0x00,0x2f,0x00,0x53,0x00,0x79,0x00,0x73,0x00,0x74,0x00,0x65,0x00,
	0x6d,0x00,0x33,0x00,0x32,0x00,0x2f,0x00,0x00 };

namespace Modules {

	UINT_PTR FindSection(CONST CHAR* section_name, UINT_PTR base, UINT32 *size) {

		UINT_PTR sec_address = 0;
		SIZE_T name_length = MbsLength(section_name);

		CONST PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, base, ((PIMAGE_DOS_HEADER)base)->e_lfanew);
		CONST PIMAGE_SECTION_HEADER sec_head = IMAGE_FIRST_SECTION(nt_head);

		for (INT i = 0; i < nt_head->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER section = &sec_head[i];

			if (name_length == MbsLength((CHAR*) section->Name)) {
				if (MemCompare(section_name, section->Name, name_length) == 0) {

					if (!section->VirtualAddress || !size) {
						return 0;
					}
					sec_address = base + section->VirtualAddress;
					*size = section->Misc.VirtualSize;
				}
			}
		}

		return sec_address;
	}

    PLDR_DATA_TABLE_ENTRY FindModuleEntry(CONST UINT32 hash) {
        CONST LIST_ENTRY *head = &(PEB_POINTER)->Ldr->InMemoryOrderModuleList;

        for (auto next = head->Flink; next != head; next = next->Flink) {
            LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            CONST UNICODE_STRING name = mod->BaseDllName;

            WCHAR buffer[MAX_PATH] = { };

            if (hash - HashStringW(WcsToLower(buffer, name.Buffer), WcsLength(name.Buffer)) == 0) {
                return mod;
            }
        }

        return nullptr;
    }

    FARPROC FindExportAddress(CONST VOID *base, CONST UINT32 hash) {
        FARPROC address = nullptr;

        CONST PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, base, ((PIMAGE_DOS_HEADER) base)->e_lfanew);
        CONST PIMAGE_EXPORT_DIRECTORY exports = RVA(PIMAGE_EXPORT_DIRECTORY, base, nt_head->OptionalHeader.DataDirectory[0].VirtualAddress);

        if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
            return address;
        }

		CONST UINT16 *ordinals = RVA(UINT16*, base, exports->AddressOfNameOrdinals);
		CONST UINT32 *functions = RVA(UINT32*, base, exports->AddressOfFunctions);
		CONST UINT32 *names = RVA(UINT32*, base, exports->AddressOfNames);
		
        for (INT index = 0; index < exports->NumberOfNames; index++) {
            CONST CHAR *name = RVA(CHAR*, base, names[index]);
            CHAR buffer[MAX_PATH] = { };

            if (hash - HashStringA(MbsToLower(buffer, name), MbsLength(name)) == 0) {
                address = RVA(FARPROC, base, functions[ordinals[index]]); // NOTE: changed to index functions by ordinals[i]
                break;
            }
        }

        return address;
    }

    BOOL LocalLdrFindExportAddress(HMODULE mod, CONST CHAR *export_name, CONST UINT16 ordinal, VOID **function) {

        PIMAGE_SECTION_HEADER section = nullptr;
        UINT8 buffer[MAX_PATH] = { };

        LPVOID text_start = nullptr;
        LPVOID text_end = nullptr;
		UINT32 sec_hash = 0;

		if (!mod) {
			return false;
		}
		if ((!export_name && !ordinal) || (export_name && ordinal)) { /* can't have both. */
			return false;
		}

		PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, mod, ((PIMAGE_DOS_HEADER)mod)->e_lfanew);
        if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

		// Locate .text section
        for (INT sec_index = 0; sec_index < nt_head->FileHeader.NumberOfSections; sec_index++) {
            CONST IMAGE_SECTION_HEADER *section = RVA(IMAGE_SECTION_HEADER*, &nt_head->OptionalHeader, nt_head->FileHeader.SizeOfOptionalHeader + (sec_index * sizeof(IMAGE_SECTION_HEADER)));

            if (!(sec_hash = HashStringA((CHAR*)section->Name, MbsLength((CHAR*)section->Name)))) {
				return false;
			}
            if (TEXT == sec_hash) {
                text_start = RVA(VOID*, mod, section->VirtualAddress);
                text_end = RVA(VOID*, text_start, section->SizeOfRawData);
                break;
            }
        }
        if (!text_start || !text_end) {
            return false;
        }

        IMAGE_DATA_DIRECTORY *data_dire = &nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (data_dire->Size) {
            CONST IMAGE_EXPORT_DIRECTORY *exports = RVA(IMAGE_EXPORT_DIRECTORY*, mod, data_dire->VirtualAddress);
            CONST UINT32 n_entries = !export_name ? exports->NumberOfFunctions : exports->NumberOfNames;

            for (auto entry_index = 0; entry_index < n_entries; entry_index++) {
                UINT32 _ordinal = 0;
                BOOL found = false;

                if (export_name) {
                    CONST UINT32 *_name_rva = RVA(UINT32*, mod, exports->AddressOfNames + entry_index * sizeof(UINT32));
                    CONST CHAR *name = RVA(CHAR*, mod, *_name_rva);

                    if (MbsCompare(name, export_name)) {
                        CONST INT16 *_ord_rva = RVA(INT16*, mod, exports->AddressOfNameOrdinals + entry_index * sizeof(UINT16));

                        _ordinal = exports->Base + *_ord_rva;
                        found = true;
                    }
                } else {
                    CONST INT16 *_ord_rva = RVA(INT16*, mod, exports->AddressOfNameOrdinals + entry_index * sizeof(INT16));
                    _ordinal = exports->Base + *_ord_rva;

                    if (_ordinal == ordinal) {
                        found = true;
                    }
                }

                if (found) {
                    UINT32 *function_rva = RVA(UINT32*, mod, exports->AddressOfFunctions + sizeof(UINT32) * (_ordinal - exports->Base));
                    VOID *fn_pointer = RVA(VOID*, mod, *function_rva);

                    if (text_start > fn_pointer || text_end < fn_pointer) { /* NOTE: this is another module... */
                        SIZE_T length = MbsLength((CHAR*)fn_pointer);
						CONST CHAR *found_name = (CHAR*)fn_pointer + length + 1; /* TODO: check that this is correct. */

						MemSet(buffer, 0, MAX_PATH);
						LDR_DATA_TABLE_ENTRY *lib_entry = FindModuleEntry(HashStringA(MbsToLower((CHAR*)buffer, found_name), length));
						if (!lib_entry || lib_entry->DllBase == mod) {
							return false;
						}

						if (!LocalLdrFindExportAddress((HMODULE)lib_entry->DllBase, found_name, 0, &fn_pointer)) {
							return false;
						}
					}

					*function = fn_pointer;
					return true;
				}
			}
		}
		return false;
	}

	// TODO: string hash function name 
    BOOL FindModulePath(EXECUTABLE *mod, const uint32 name_hash) {
        HEXANE;

		WCHAR filename[MAX_PATH] = { };
		WIN32_FIND_DATAW data = { };
		HANDLE handle = { };
		BOOL success = false;

        if (!name_hash) {
            goto defer;
        }

        if (!(mod->local_name = (WCHAR*)Malloc(MAX_PATH))) {
            goto defer;
        }

		MemCopy(B_PTR(filename), B_PTR(sys32), sizeof(sys32));
		WcsConcat(filename, (WCHAR*)dot_dll); // NOTE: sould not do this until we've found the dll

		handle = ctx->win32.FindFirstFileW(filename, &data);
		if (INVALID_HANDLE_VALUE == handle) {
			goto defer;
		}

		do {
			MemSet(filename, 0, MAX_PATH);
			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				continue;
			} else {
				if (HashStringW(WcsToLower(filename, data.cFileName), WcsLength(data.cFileName)) - name_hash == 0) {
					MemCopy(filename, data.cFileName, WcsLength(data.cFileName) * sizeof(WCHAR));
				}
			}
		} while (ctx->win32.FindNextFileW(handle, &data) != 0);

		if (!filename[0]) {
			goto defer;
		}

		MemCopy(B_PTR(mod->local_name), (CHAR*)sys32, sizeof(sys32));
		WcsConcat(mod->local_name, (WCHAR*)filename);

        mod->cracked_name = (WCHAR*) Malloc(WcsLength(filename) * sizeof(WCHAR) + 1);
		if (!mod->cracked_name) {
			goto defer;
		}

		MemCopy(mod->cracked_name, filename, WcsLength(filename) * sizeof(WCHAR) + 1);
		success = true;

	defer:
		if (handle) {
			ctx->win32.FindClose(handle);
		}
        return success;
    }

    VOID InsertTailList(LIST_ENTRY *CONST head, LIST_ENTRY *CONST entry) {
        PLIST_ENTRY blink = head->Blink;

        entry->Flink = head;
        entry->Blink = blink;
        blink->Flink = entry;
        head->Blink	 = entry;
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
        ULONG hash = LdrHashEntry(entry->BaseDllName, true);

        InsertTailList(&hash_table[hash], &entry->HashLinks);
        InsertTailList(&peb->Ldr->InLoadOrderModuleList, &entry->InLoadOrderLinks);
        InsertTailList(&peb->Ldr->InMemoryOrderModuleList, &entry->InMemoryOrderLinks);
        InsertTailList(&peb->Ldr->InInitializationOrderModuleList, &entry->InInitializationOrderLinks);

        return true;
    }

	BOOL ResolveEntries(CONST EXECUTABLE *mod, PIMAGE_THUNK_DATA thunk_a, PIMAGE_THUNK_DATA thunk_b, VOID *lib) {
		BOOL success = false;

		for (; thunk_b && thunk_b->u1.Function; thunk_a++, thunk_b++) {
			if (thunk_a->u1.Function != thunk_b->u1.AddressOfData) { /* already resolved */
				continue;
			}

			if (IMAGE_SNAP_BY_ORDINAL(thunk_b->u1.Ordinal)) {
				if (!LocalLdrFindExportAddress((HMODULE)lib, nullptr, (UINT16)thunk_b->u1.Ordinal, (VOID**)&thunk_a->u1.Function)) {
					goto defer;
				}
			} else {
				PIMAGE_IMPORT_BY_NAME import_name = RVA(PIMAGE_IMPORT_BY_NAME, mod->base, thunk_b->u1.AddressOfData);
				if (!LocalLdrFindExportAddress((HMODULE)lib, import_name->Name, 0, (VOID**)&thunk_a->u1.Function)) {
					goto defer;
				}
			}
		}
		success = true;

	defer:
		return success;
	}

	BOOL ResolveImports(CONST EXECUTABLE *mod) {

		UINT8 buffer[MAX_PATH] = { };
		BOOL success = false;

		struct ImportSections {
			UINT32 directory;
			BOOL delayed;
		};

		ImportSections import_sections[] = { 
			{ IMAGE_DIRECTORY_ENTRY_IMPORT, false },
			{ IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, true },
		};

		for (auto sec_index = 0; sec_index < ARRAY_LEN(import_sections); sec_index++) {
			PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY)&mod->nt_head->OptionalHeader.DataDirectory[import_sections[sec_index].directory]; 
			PIMAGE_IMPORT_DESCRIPTOR import_desc = nullptr;
			PIMAGE_DELAYLOAD_DESCRIPTOR delay_desc = nullptr;

			if (directory->Size) {
				BOOL delayed = import_sections[sec_index].delayed;
				VOID *descriptor = nullptr;

				if (delayed) {
					delay_desc = RVA(PIMAGE_DELAYLOAD_DESCRIPTOR, mod->base, directory->VirtualAddress);
					descriptor = delay_desc;
				} else {
					import_desc = RVA(PIMAGE_IMPORT_DESCRIPTOR, mod->base, directory->VirtualAddress);
					descriptor = import_desc;
				}

				while (descriptor) {
					VOID *lib = nullptr;
					UINT32 hash = 0;

					PIMAGE_THUNK_DATA thunk_a = nullptr;
					PIMAGE_THUNK_DATA thunk_b = nullptr;

					MemSet(buffer, 0, MAX_PATH);

					CONST DWORD rva = delayed ? ((PIMAGE_DELAYLOAD_DESCRIPTOR)descriptor)->DllNameRVA : ((PIMAGE_IMPORT_DESCRIPTOR)descriptor)->Name;
					CONST CHAR *name = RVA(CHAR*, mod->base, rva);

					if (U_PTR(name) == U_PTR(mod->base)) {
						success = true;  // Return to start of image. Likely end of descriptor.
						goto defer;
					}
					if (!(hash = HashStringA(MbsToLower((CHAR*)buffer, name), MbsLength(name)))) {
						goto defer;
					}

					/* one must succeed */
					if (PLDR_DATA_TABLE_ENTRY dep = FindModuleEntry(hash)) {
						volatile auto temp = dep->DllBase;  /* Prevent compiler optimizations */
						lib = temp;
					} else {
						/*
						  TODO: Find the first module import and follow control flow. Find out why the same module is repeatedly queried.
						  TODO: Start using github issues to create TODO.
						 */
						PEXECUTABLE next_load = ImportModule(LoadLocalFile, hash, nullptr, 0, nullptr, false);
						if (!next_load) {
							goto defer;
						}

						lib = next_load->base;
					}

					thunk_a = RVA(PIMAGE_THUNK_DATA, mod->base, delayed ? ((PIMAGE_DELAYLOAD_DESCRIPTOR)descriptor)->ImportAddressTableRVA : ((PIMAGE_IMPORT_DESCRIPTOR)descriptor)->FirstThunk);
					thunk_b = RVA(PIMAGE_THUNK_DATA, mod->base, delayed ? ((PIMAGE_DELAYLOAD_DESCRIPTOR)descriptor)->ImportNameTableRVA : ((PIMAGE_IMPORT_DESCRIPTOR)descriptor)->OriginalFirstThunk);

					if (!ResolveEntries(mod, thunk_a, thunk_b, lib)) {
						goto defer;
					}

					descriptor = delayed ? (VOID*)((PIMAGE_DELAYLOAD_DESCRIPTOR)descriptor + 1) : (VOID*)((PIMAGE_IMPORT_DESCRIPTOR)descriptor + 1);
				}
			}
		}
		success = true;

	defer:
		return success;
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
            SIZE_T begin  = 0;

            PIMAGE_NT_HEADERS nt_head = RVA(PIMAGE_NT_HEADERS, entry->DllBase, ((PIMAGE_DOS_HEADER) entry->DllBase)->e_lfanew);
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);

            for (int sec_index = 0; sec_index < nt_head->FileHeader.NumberOfSections; sec_index++) {
                UINT32 sec_hash = HashStringA((CHAR*) section->Name, MbsLength((char*) section->Name));
                UINT32 dot_data = DATA;

                if (MemCompare((LPVOID)&dot_data, (LPVOID)&sec_hash, sizeof(UINT32)) == 0) {
                    begin = (SIZE_T) entry->DllBase + section->VirtualAddress;
                    length = section->Misc.VirtualSize;
                    break;
                }

                ++section;
            }

            for (INT index = 0; index < length - sizeof(SIZE_T); ++begin, ++index) {
                SIZE_T stRet = MemCompare((LPVOID)begin, &node, sizeof(SIZE_T));

                if (stRet == sizeof(SIZE_T)) {
                    end = begin;
                    break;
                }
            }

            if (!end) {
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

		PIMAGE_DATA_DIRECTORY relocdir = nullptr;
		UINT_PTR base_rva  = 0;
		BOOL success = false;
		
		if (mod->nt_head->Signature != IMAGE_NT_SIGNATURE) {
			return false;
		}

        mod->base = B_PTR(mod->nt_head->OptionalHeader.ImageBase);
        mod->base_size = (SIZE_T) mod->nt_head->OptionalHeader.SizeOfImage;

        if (!NT_SUCCESS(ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (VOID**) &mod->base, 0, &mod->base_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) ||
            U_PTR(mod->base) != mod->nt_head->OptionalHeader.ImageBase) {

            mod->base = 0;
            mod->base_size = (size_t) mod->nt_head->OptionalHeader.SizeOfImage;

			// NOTE: test non-prefered image base
            if (!NT_SUCCESS(ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), (VOID**) &mod->base, 0, &mod->base_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) ||
				mod->base_size != mod->nt_head->OptionalHeader.SizeOfImage) {
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
					case IMAGE_REL_BASED_DIR64:   *(UINT32*) (B_PTR(mod->base) + reloc->VirtualAddress + head->Offset) += base_rva; break;
					case IMAGE_REL_BASED_HIGHLOW: *(UINT32*) (B_PTR(mod->base) + reloc->VirtualAddress + head->Offset) += (UINT32) base_rva; break;
					case IMAGE_REL_BASED_HIGH:    *(UINT32*) (B_PTR(mod->base) + reloc->VirtualAddress + head->Offset) += HIWORD(base_rva); break;
					case IMAGE_REL_BASED_LOW:     *(UINT32*) (B_PTR(mod->base) + reloc->VirtualAddress + head->Offset) += LOWORD(base_rva); break;
                    }
                    head++;
                } while (B_PTR(head) != B_PTR(reloc) + reloc->SizeOfBlock);

                reloc = (PIMAGE_BASE_RELOCATION) head;
            } while (reloc->VirtualAddress);
        }

        mod->nt_head->OptionalHeader.ImageBase = U_PTR(mod->base); // set the prefered base to the real base
		success = true;

	defer:
        return success;
    }

    BOOL AddModuleEntry(PLDR_DATA_TABLE_ENTRY entry, CONST VOID *base) {
        HEXANE;

        PRTL_RB_TREE index = nullptr;
		if (!(index = FindModuleIndex())) {
            return false;
        }

        PLDR_DATA_TABLE_ENTRY node = (PLDR_DATA_TABLE_ENTRY) ((SIZE_T)index - offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));
        BOOL right_hand = false;

        do {
            // NOTE: looking for correct in-memory order placement according to RB Tree
            if (base < node->DllBase) {
                if (!node->BaseAddressIndexNode.Left) {
                    break;
                }
                node = (PLDR_DATA_TABLE_ENTRY) ((SIZE_T)node->BaseAddressIndexNode.Left - offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));

            } else if (base > node->DllBase) {
                if (!node->BaseAddressIndexNode.Right) {
                    right_hand = true;
                    break;
                }
                node = (PLDR_DATA_TABLE_ENTRY) ((SIZE_T)node->BaseAddressIndexNode.Right - offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));

            } else {
                node->DdagNode->LoadCount++;
            }
        } while (true);

        if (!ctx->win32.RtlRbInsertNodeEx(index, &node->BaseAddressIndexNode, right_hand, &entry->BaseAddressIndexNode)) {
            return false;
        }

        return true;
    }

    BOOL ReadModule(EXECUTABLE *mod) {
        HEXANE;

		// TODO: INVALID_FILE_HANDLE on one of the dependencies
		BOOL success = false;
        HANDLE handle = ctx->win32.CreateFileW(mod->local_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
			goto defer;
        }

        mod->buf_size = ctx->win32.GetFileSize(handle, nullptr);
        if (mod->buf_size == INVALID_FILE_SIZE) {
			goto defer;
        }

        if (!(mod->buffer = (PBYTE)Malloc(mod->buf_size)) ||
			!ctx->win32.ReadFile(handle, mod->buffer, mod->buf_size, (DWORD*)&mod->buf_size, nullptr)) {
            goto defer;
        }

		success = true;

	defer:
		if (!success && mod->buffer) {
            Free(mod->buffer);
		}
		if (handle && handle != INVALID_HANDLE_VALUE) {
			ctx->win32.NtClose(handle);
		}

        return success;
    }

    BOOL LinkModule(EXECUTABLE *mod) {
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

        entry->ReferenceCount    = 1;
        entry->LoadReason        = LoadReasonDynamicLoad;
        entry->OriginalBase      = mod->nt_head->OptionalHeader.ImageBase;
        entry->BaseNameHashValue = LdrHashEntry(entry->BaseDllName, false);

        // correctly add the base address to the entry
        AddModuleEntry(entry, (LPVOID) mod->base);

        entry->ImageDll = true;
        entry->LoadNotificationsSent = true; 
        entry->EntryProcessed = true;
        entry->InLegacyLists  = true;
        entry->InIndexes      = true;
        entry->ProcessAttachCalled = true;
        entry->InExceptionTable    = false;
        entry->DllBase       = (LPVOID)mod->base;
        entry->SizeOfImage   = mod->nt_head->OptionalHeader.SizeOfImage;
        entry->TimeDateStamp = mod->nt_head->FileHeader.TimeDateStamp;
        entry->BaseDllName   = base_name;
        entry->FullDllName   = full_name;
        entry->ObsoleteLoadCount = 1;

        entry->Flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;
        entry->DdagNode = (PLDR_DDAG_NODE) Malloc(sizeof(LDR_DDAG_NODE));

        if (!entry->DdagNode) {
            return false;
        }

        entry->NodeModuleLink.Flink = &entry->DdagNode->Modules;
        entry->NodeModuleLink.Blink = &entry->DdagNode->Modules;

        entry->DdagNode->Modules.Flink = &entry->NodeModuleLink;
        entry->DdagNode->Modules.Blink = &entry->NodeModuleLink;
        entry->DdagNode->State = LdrModulesReadyToRun;
        entry->DdagNode->LoadCount = 1;

        AddHashTableEntry(entry);
        entry->EntryPoint = (PLDR_INIT_ROUTINE) RVA(LPVOID, mod->base, mod->nt_head->OptionalHeader.AddressOfEntryPoint);

        return true;
    }

	BOOL BeginExecution(PEXECUTABLE mod) {
		HEXANE;
		
		DWORD protect = 0;
		BOOL success = false;
		DLLMAIN dll_main = nullptr;
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(mod->nt_head);

		for (int i = 0; i < mod->nt_head->FileHeader.NumberOfSections; i++) {

			if (section->SizeOfRawData) {
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

				LPVOID base = RVA(LPVOID, mod->base, section->VirtualAddress);
				SIZE_T region_size = section->SizeOfRawData;
#if _M_X64
				if (!ctx->win32.NtProtectVirtualMemory(NtCurrentProcess(), &base, &region_size, protect, &protect)) {
					goto defer;
				}
#else
				/* ?? */
#endif
			}
			if (!ctx->win32.FlushInstructionCache(NtCurrentProcess(), nullptr, 0)) {
				goto defer;
			}

			PIMAGE_DATA_DIRECTORY data_dire = &mod->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

			if (data_dire->Size) {
				PIMAGE_TLS_DIRECTORY tls = RVA(PIMAGE_TLS_DIRECTORY, mod->base, data_dire->VirtualAddress);
				PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

				for (; *callback; callback++) {
					(*callback)((LPVOID)mod->base, DLL_PROCESS_ATTACH, nullptr);
				}
			}
			if (!mod->nt_head->OptionalHeader.AddressOfEntryPoint) {
				success = true;
				goto defer;
			}

			dll_main = RVA(DLLMAIN, mod->base, mod->nt_head->OptionalHeader.AddressOfEntryPoint);
			if (!dll_main((HINSTANCE)mod->base, DLL_PROCESS_ATTACH, nullptr)) {
				goto defer;
			}
		}
		success = true;

	defer:
		return success;
	}

	PEXECUTABLE ImportModule(CONST UINT32 load_type, CONST UINT32 name_hash, UINT8 *memory, CONST UINT32 mem_size, WCHAR *name, BOOL cache) {
        HEXANE;

        // Code based off of https://github.com/bats3c/DarkLoadLibrary
        PEXECUTABLE mod = (PEXECUTABLE)Malloc(sizeof(EXECUTABLE));
        if (!mod) {
            return nullptr;
        }

        mod->success = false;
        mod->link = true;

		if (name_hash) {
			if (LDR_DATA_TABLE_ENTRY *check_mod = FindModuleEntry(name_hash)) {
				mod->base = B_PTR(check_mod->DllBase);
				mod->success = true;

				goto defer;
			}
		}

		switch (LOWORD(load_type)) {
		case LoadLocalFile: {
			__debugbreak();
			if (!FindModulePath(mod, name_hash) || !ReadModule(mod)) {
				goto defer;
			}
			break;
		}
		case LoadMemory: {
			mod->buf_size = mem_size;
			mod->buffer = memory;
			mod->cracked_name = name;
			mod->local_name = name;

			if (name == nullptr) {
				goto defer;
			}
			break;
		}
		default:
			goto defer;
		}

        if (load_type & NoLink) {
            mod->link = false;
		}

        if (!name) {
            name = mod->cracked_name;
        }

		FindHeaders(mod);
        if (!ImageCheckArch(mod)) {
            goto defer;
        }

		if (!MapModule(mod) || !ResolveImports(mod)) {
			goto defer;
		}
		if (mod->link) {
            if (!LinkModule(mod)) {
                goto defer;
            }
        }
		if (!BeginExecution(mod)) {
			goto defer;
		}

		mod->success = true;

	defer:
		if (mod) {
			if (!mod->success) {
				CleanupModule(&mod, true);
			} else {
				if (!cache) {
					CleanupModule(&mod, false);
				}
			}
		}

        return mod;
    }

	VOID CleanupModule(EXECUTABLE **mod, BOOL destroy) {
		HEXANE;

		if (mod && *mod) {
			if ((*mod)->buffer) {
				MemSet((*mod)->buffer, 0, (*mod)->buf_size);
				Free((*mod)->buffer);
				(*mod)->buffer = nullptr;
			}
			if ((*mod)->local_name) {
				MemSet((*mod)->local_name, 0, MAX_PATH);
				Free((*mod)->local_name);
				(*mod)->local_name = nullptr;
			}
			if ((*mod)->cracked_name) {
				MemSet((*mod)->cracked_name, 0, MAX_PATH);
				Free((*mod)->cracked_name);
				(*mod)->cracked_name = nullptr;
			}
			if (destroy) {
				if ((*mod)->base) {													
					ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), (VOID**) &(*mod)->base, &(*mod)->base_size, MEM_RELEASE); 
					(*mod)->base = nullptr;											
				}																
				Free(*mod);													
				*mod = nullptr;												
			}
		}
	}

    BOOL ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal) {
        // TODO:
        return false;
    }
}
