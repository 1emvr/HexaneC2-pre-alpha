#include <commands/include/registry.hpp>

LPSTR FormatResultError(LRESULT Result) {
    HEXANE

    LPSTR Buffer = { };
    Ctx->win32.FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, Result, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&Buffer, 0, nullptr);

    return Buffer;
}

LSTATUS RegCreateSubkey(HKEY Key, LPSTR Subkey, LPSTR Name, DWORD Value) {
    HEXANE

    LSTATUS Result  = 0;
    HKEY hkOpen     = { };

    if ((Ctx->win32.RegOpenKeyExA(Key, Subkey, 0, KEY_READ, &hkOpen)) != ERROR_SUCCESS) {
        if ((Result = Ctx->win32.RegCreateKeyExA(Key, Subkey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, nullptr, &hkOpen, nullptr)) != ERROR_SUCCESS) {
            goto defer;
        }
    }
    if ((Result = Ctx->win32.RegSetValueExA(hkOpen, Name, 0, REG_DWORD, (CONST PBYTE)&Value, sizeof(DWORD))) != ERROR_SUCCESS) {
        goto defer;
    }

    defer:
    if (hkOpen) {
        Ctx->win32.RegCloseKey(hkOpen);
    }

    return Result;
}
