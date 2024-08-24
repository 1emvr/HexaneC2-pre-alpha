#include <windows.h>
#include <stdio.h>

#define FNV_OFFSET      (const unsigned int) 2166136261
#define FNV_PRIME	    (const unsigned int) 16777619

ULONG GetHashFromStringW(wchar_t const *string, size_t length) {

    auto hash = FNV_OFFSET;
    if (string) {
        for (auto i = 0; i < length; i++) {
            hash ^= string[i];
            hash *= FNV_PRIME;
        }
    }
    return hash;
}

wchar_t x_toLowerW(const wchar_t c) {
    if (c >= 0x0041 && c <= 0x005A) {
        return c + (0x0061 - 0x0041);
    }

    return c;
}

wchar_t *x_wcsToLower(wchar_t *const dst, const wchar_t *const src) {

    const auto len = wcslen(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = x_toLowerW(src[i]);
    }

    dst[len] = 0x0000;
    return dst;
}

int main() {

    printf("starting...\n");
    wchar_t buffer[MAX_PATH] = { };
    wchar_t lower[MAX_PATH] = { };

    mbstowcs(buffer, "ntdll.dll", strlen("ntdll.dll"));
    auto hash = GetHashFromStringW(x_wcsToLower(lower, buffer), wcslen(buffer));

    printf("%ls = 0x%lx\n", buffer, hash);
}