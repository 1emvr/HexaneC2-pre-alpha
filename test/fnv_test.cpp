#include <windows.h>
#include <cstdint>
#include <stdio.h>

#define FNV_OFFSET      (const unsigned int) 2166136261
#define FNV_PRIME	    (const unsigned int) 16777619

ULONG HashStringA(char const *string, size_t length) {

    auto hash = FNV_OFFSET;
    if (string) {
        for (auto i = 0; i < length; i++) {
            hash ^= string[i];
            hash *= FNV_PRIME;
        }
    }
    return hash;
}

ULONG HashStringW(wchar_t const *string, size_t length) {

    auto hash = FNV_OFFSET;
    if (string) {
        for (auto i = 0; i < length; i++) {
            hash ^= string[i];
            hash *= FNV_PRIME;
        }
    }
    return hash;
}

wchar_t x_tolower_w(const wchar_t c) {
    if (c >= 0x0041 && c <= 0x005A) {
        return c + (0x0061 - 0x0041);
    }

    return c;
}

char x_tolower_a(const char c) {
    if (c >= 0x41 && c <= 0x5A) {
        return c + (0x61 - 0x41);
    }

    return c;
}

wchar_t *x_wcs_tolower(wchar_t *const dst, const wchar_t *const src) {

    const auto len = wcslen(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = x_tolower_w(src[i]);
    }

    dst[len] = 0x0000;
    return dst;
}

char *x_mbs_tolower(char *const dst, const char *const src) {

    const auto len = strlen(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = x_tolower_a((uint8_t) src[i]);
    }

    dst[len] = 0x00;
    return dst;
}

int main() {

    printf("starting...\n");
    wchar_t wcs_lower[MAX_PATH] = { };
    char mbs_lower[MAX_PATH]    = { };

    auto wcs_hash = HashStringW(x_wcs_tolower(wcs_lower, L"nTdll.dll"), wcslen(L"ntdll.dll"));
    auto mbs_hash = HashStringA(x_mbs_tolower(mbs_lower, "ntdll.Dll"), strlen("ntdll.dll"));

    printf("%ls = 0x%lx\n", L"ntdll.dll", wcs_hash);
    printf("%s = 0x%lx\n", "ntdll.dll", mbs_hash);
}