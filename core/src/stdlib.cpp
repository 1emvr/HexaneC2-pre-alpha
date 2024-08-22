#include <core/include/stdlib.hpp>
void x_memcpy (void *dst, const void *const src, const size_t n) {

    const auto a = S_CAST(uint8_t*, dst);
    const auto b = S_CAST(const uint8_t*, src);

    for (size_t i = 0; i < n; i++) {
        a[i] = b[i];
    }
}

void *x_memset (void *const dst, const int val, size_t len) {

    auto ptr = S_CAST(uint8_t*, dst);
    while (len-- > 0) {
        *ptr++ = val;
    }
    return dst;
}

void x_strcpy (char *dst, const char *src) {

    while ((*dst = *src) != 0x0) {
        dst++;
        src++;
    }
}

size_t x_strncmp (const char *str1, const char *str2, size_t len) {

    while (len && *str1 && (*str1 == *str2)) {
        len--; str1++; str2++;

        if (len == 0) {
            return  0;
        }
    }
    return len ? (unsigned char)*str1 - (unsigned char)*str2 : 0;
}


int x_strcmp (const char *str1, const char *str2) {

    while (*str1 && *str1 == *str2) {
        str1++; str2++;
    }

    return S_CAST(uint8_t, *str1) - S_CAST(uint8_t, *str2);
}

int x_memcmp (const void *const ptr1, const void *const ptr2, size_t len) {

    const auto *p1 = S_CAST(const uint8_t*, ptr1);
    const auto *p2 = S_CAST(const uint8_t*, ptr2);

    while (len--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }

        p1++; p2++;
    }

    return 0;
}

char *x_strcat (char *const str1, const char *const str2) {

    x_strcpy(str1 + x_strlen(str1), str2);
    return str1;
}

size_t x_strlen (const char* str) {

    auto len = 0;
    const auto s_str = str;

    while (s_str[len] != 0x00) {
        len++;
    }

    return len;
}

size_t x_wcslen (const wchar_t *const s) {

    size_t len = 0;
    const auto s_str = s;

    while (s_str[len] != 0x00) {
        len++;
    }

    return len;
}

void x_wcscpy (wchar_t *dest, const wchar_t *src) {

    while ((*dest = *src) != 0x0000) {
        dest++;
        src++;
    }
}

int x_wcscmp (const wchar_t *str1, const wchar_t *str2) {

    for (; *str1 == *str2; str1++, str2++) {
        if (*str1 == 0x0000) {
            return 0;
        }
    }
    return *str1 < *str2 ? -1 : +1;
}

wchar_t *x_wcscat (wchar_t *const str1, const wchar_t *const str2) {

    x_wcscpy(str1 + x_wcslen(str1), str2 );
    return str1;
}

wchar_t x_toLowerW(const wchar_t c) {
    if (c >= 0x0041 && c <= 0x005A) {
        return c + (0x0061 - 0x0041);
    }

    return c;
}

char x_toLowerA(const char c) {
    if (c >= 0x41 && c <= 0x5A) {
        return c + (0x61 - 0x41);
    }

    return c;
}

wchar_t *x_wcsToLower(wchar_t *const dst, const wchar_t *const src) {

    const auto len = x_wcslen(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = x_toLowerW(src[i]);
    }

    dst[len] = 0x0000;
    return dst;
}

char *x_mbsToLower(char *const dst, const char *const src) {

    const auto len = x_strlen(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = x_toLowerA(S_CAST(uint8_t, src[i]));
    }

    dst[len] = 0x00;
    return dst;
}

size_t x_mbstowcs (wchar_t *dst, const char *src, const size_t size) {

    auto count = size;
    while (--count) {
        if (!(*dst++ = *src++)) {
            return size - count - 1;
        }
    }

    return size - count;
}

size_t x_wcstombs (char *const str, const wchar_t *wcs, size_t size) {

    auto count = 0;
    while (count < size) {
        if (*wcs > 255) {
            return -1;
        }

        str[count] = *wcs;
        if (*wcs++ == 0x0000) {
            break;
        }
        count++;
    }

    str[count] = 0;
    return count;
}

int x_mbsEndsWith (const char *string, const char *const end) {

    uint32_t length1 = 0;
    uint32_t length2 = 0;

    if (!string || !end) {
        return FALSE;
    }

    length1 = x_strlen(string);
    length2 = x_strlen(end);

    if (length1 < length2) {
        return FALSE;
    }
    string = &string[length1 - length2];
    return x_strcmp(string, end) == 0;
}

int x_wcsEndsWith (const wchar_t *string, const wchar_t *const end) {

    uint32_t length1 = 0;
    uint32_t length2 = 0;

    if ( !string || !end ) {
        return FALSE;
    }

    length1 = x_wcslen(string);
    length2 = x_wcslen(end);

    if ( length1 < length2 ) {
        return FALSE;
    }

    string = &string[ length1 - length2 ];
    return x_wcscmp(string, end) == 0;
}
