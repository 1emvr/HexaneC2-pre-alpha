#include "core/corelib.hpp"
#pragma comment (lib, "mscoree.lib")

#define UNMANAGED_PROCESSES   0
#define MANAGED_PROCESSES     1

VOID EnumDotNetProcesses(PPARSER Parser) {

    PSTREAM Stream  = Stream::CreateStreamWithHeaders(TypeResponse);
    PROCESSENTRY32 Entries = { };
    HANDLE Snapshot = { };
    HANDLE hProcess = { };

    DWORD Size = 0;
    BOOL Loaded = FALSE;
    WCHAR Buffer[1024];

    IEnumUnknown *pEnum = { };
    ICLRMetaHost *pMetaHost = { };
    ICLRRuntimeInfo *pRuntime = { };

    Entries.dwSize = sizeof(PROCESSENTRY32);

    switch (Parser::UnpackDword(Parser)) {
        case MANAGED_PROCESSES: {
            if (
                (Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE ||
                !Process32First(Snapshot, &Entries)) {
                return;
            }
            do {
                if (!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Entries.th32ProcessID))) {
                    continue;
                }

                Size = ARRAY_LEN(Buffer);

                if (SUCCEEDED(CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost)))) {
                    if (SUCCEEDED(pMetaHost->EnumerateInstalledRuntimes(&pEnum))) {
                        while (S_OK == pEnum->Next(1, (IUnknown **) &pRuntime, nullptr)) {

                            if (pRuntime->IsLoaded(hProcess, &Loaded) == S_OK && Loaded == TRUE) {
                                if (SUCCEEDED(pRuntime->GetVersionString(Buffer, &Size))) {

                                    Stream::PackDword(Stream, Entries.th32ProcessID);
                                    Stream::PackString(Stream, Entries.szExeFile);
                                    Stream::PackWString(Stream, Buffer);
                                }
                            }
                            pRuntime->Release();
                        }
                    }
                }

                if (pMetaHost) { pMetaHost->Release(); }
                if (pRuntime) { pRuntime->Release(); }
                if (pEnum) { pEnum->Release(); }

                CloseHandle(hProcess);
            } while (Process32Next(Snapshot, &Entries));

            CloseHandle(Snapshot);
        }
        case UNMANAGED_PROCESSES: {

        }
        default:
    }
}