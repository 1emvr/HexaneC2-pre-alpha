#include <../../monolith.hpp>
#include <metahost.h>
#include <iostream>
#pragma comment (lib, "mscoree.lib")

#define write(x) std::cout << x << std::endl
#define error(x) std::cerr << x << GetLastError() << std::endl
#define process(p, n, b) std::wcout << L"Process ID: " <<  p << L", Name: " << n << L", .NET Version: " << b << std::endl

VOID EnumDotNetProcesses() {

    HANDLE Snapshot = { };
    HANDLE hProcess = { };

    DWORD Size = 0;
    BOOL Loaded = FALSE;
    WCHAR Buffer[1024];

    IEnumUnknown *pEnum = { };
    ICLRMetaHost *pMetaHost = { };
    ICLRRuntimeInfo *pRuntime = { };

    PROCESSENTRY32 Entries = { };

    if ((Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) {
        error("Tlhelp32Snapshot failed: ");
        return;
    }
    Entries.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(Snapshot, &Entries)) {
        error("Process32First failed: ");
        return;
    }

    write("Eunumerating processes...");
    do {
        if (!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Entries.th32ProcessID))) {
            continue;
        }
        Size = ARRAY_LEN(Buffer);

        if (SUCCEEDED(CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost)))) {
            if (SUCCEEDED(pMetaHost->EnumerateInstalledRuntimes(&pEnum))) {
                while (S_OK == pEnum->Next(1, (IUnknown**) &pRuntime, nullptr)) {

                    if (pRuntime->IsLoaded(hProcess, &Loaded) == S_OK && Loaded == TRUE) {
                        if (SUCCEEDED(pRuntime->GetVersionString(Buffer, &Size))) {
                            process(Entries.th32ProcessID, Entries.szExeFile, Buffer);
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

    write("finished...");
    CloseHandle(Snapshot);
}

int main() {
    EnumDotNetProcesses();
    write("Exiting...");
}