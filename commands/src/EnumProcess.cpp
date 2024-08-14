#include <core/corelib.hpp>
#include <core/dotnet.hpp>
#pragma comment (lib, "mscoree.lib")

#define UNMANAGED_PROCESS   0
#define MANAGED_PROCESS     1

VOID EnumProcesses(_parser *parser) {

    _stream *stream          = Stream::CreateStreamWithHeaders(TypeResponse);
    PROCESSENTRY32 Entries  = { };
    HANDLE Snapshot         = { };
    HANDLE hProcess         = { };

    IEnumUnknown *pEnum         = { };
    ICLRMetaHost *pMetaHost     = { };
    ICLRRuntimeInfo *pRuntime   = { };

    DWORD Type  = Parser::UnpackDword(parser);
    DWORD Size  = 0;
    WCHAR Buffer[1024];
    BOOL Loaded = FALSE;

    Entries.dwSize = sizeof(PROCESSENTRY32);
    Size = ARRAY_LEN(Buffer);

    if (
        (Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE ||
        !Process32First(Snapshot, &Entries)) {
        return;
    }
    do {
        if (!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Entries.th32ProcessID))) {
            continue;
        }

        BOOL isManagedProcess = FALSE;

        if (SUCCEEDED(CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost)))) {
            if (SUCCEEDED(pMetaHost->EnumerateInstalledRuntimes(&pEnum))) {
                while (S_OK == pEnum->Next(1, (IUnknown **) &pRuntime, nullptr)) {

                    if (pRuntime->IsLoaded(hProcess, &Loaded) == S_OK && Loaded == TRUE) {
                        isManagedProcess = TRUE;

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

        if (!isManagedProcess && Type == UNMANAGED_PROCESS) {
            Stream::PackDword(Stream, Entries.th32ProcessID);
            Stream::PackString(Stream, Entries.szExeFile);
        }

        if (pMetaHost) { pMetaHost->Release(); }
        if (pRuntime) { pRuntime->Release(); }
        if (pEnum) { pEnum->Release(); }

        CloseHandle(hProcess);
    } while (Process32Next(Snapshot, &Entries));

    CloseHandle(Snapshot);
}
