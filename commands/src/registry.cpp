#include <commands/include/registry.hpp>

LPSTR FormatResultError(LRESULT Result) {

    char buffer[MAX_PATH] = { };
    char *message = (char*) Malloc(MAX_PATH);

    uint32_t flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

    Ctx->win32.FormatMessageA(flags, nullptr, Result, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) buffer, 0, nullptr);
    MemCopy(message, buffer, MAX_PATH);

    Free(buffer);
    return message;
}

LSTATUS RegCreateDwordSubkey(HKEY key, const char* const subkey, const char* const name, uint32_t value) {

    LSTATUS result = 0;
    HKEY hk_open = { };

    if (Ctx->win32.RegOpenKeyExA(key, subkey, 0, KEY_READ, &hk_open) != ERROR_SUCCESS) {
        if ((result = Ctx->win32.RegCreateKeyExA(key, subkey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY | KEY_SET_VALUE, nullptr, &hk_open, nullptr)) != ERROR_SUCCESS) {
            goto defer;
        }
    }

    result = Ctx->win32.RegSetValueExA(hk_open, name, 0, REG_DWORD, B_PTR(&value), sizeof(DWORD));

    defer:
    if (hk_open) {
        Ctx->win32.RegCloseKey(hk_open);
    }

    return result;
}
