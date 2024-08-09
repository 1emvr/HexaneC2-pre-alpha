#include <core/include/cruntime.hpp>

void x_memcpy (void *dst, const void *src, size_t n) {

    auto a = S_CAST(uint8_t*, dst);
    auto b = S_CAST(const uint8_t*, src);

    for (size_t i = 0; i < n; i++) {
        a[i] = b[i];
    }
}

void *x_memset (void *dst, int val, size_t len) {

    auto *ptr = S_CAST(uint8_t*, dst);
    while (len-- > 0) {
        *ptr++ = val;
    }
    return dst;
}

void x_strcpy (char *dst, char const *src) {

    while ((*dst = *src) != NULTERM) {
        dst++;
        src++;
    }
}

size_t x_strncmp (char *str1, char *str2, size_t len) {

    while ( len && *str1 && (*str1 == *str2) ) {
        len--;
        str1++;
        str2++;

        if (len == 0) {
            return  0;
        }
        return *str1 - *str2;
    }
    return len;
}

int x_strcmp (char *str1, char *str2) {

    for (; *str1 == *str2; str1++, str2++) {
        if (*str1 == NULTERM) {
            return 0;
        }
    } return *str1 < *str2 ? -1 : +1;
}

int x_memcmp (const void *str1, const void *str2, size_t count) {

    const auto *s1 = S_CAST(const uint8_t*, str1);
    const auto *s2 = S_CAST(const uint8_t*, str2);

    while (count-- > 0) {

        if (*s1++ != *s2++) {
            return s1[-1] < s2[-1] ? -1 : 1;
        }
    }

    return 0;
}

char *x_strcat (char *str1, char *str2) {

    x_strcpy(str1 + x_strlen(str1), str2);
    return str1;
}

size_t x_strlen (const char* str) {

    size_t len = 0;
    volatile auto s_str = (char*) str;

    while (s_str[len] != (char)0x00) {
        len++;
    }

    return len;
}

size_t x_wcslen (const wchar_t *str) {

    size_t len = 0;
    volatile auto s_str = (wchar_t*) str;

    while (s_str[len] != (wchar_t)0x00) {
        len++;
    }

    return len;
}

void x_wcscpy (wchar_t *dest, wchar_t const *src) {

    while ((*dest = *src) != 0x0000) {
        dest++;
        src++;
    }
}

int x_wcscmp (wchar_t *str1, wchar_t *str2) {

    for (; *str1 == *str2; str1++, str2++) {
        if (*str1 == 0x0000) {
            return 0;
        }
    }
    return *S_CAST(wchar_t*, str1) < *S_CAST(wchar_t*, str2) ? -1 : +1;
}

wchar_t *x_wcscat (wchar_t *str1, wchar_t *str2) {

    x_wcscpy(str1 + x_wcslen(str1), str2 );
    return str1;
}

wchar_t x_toLowerW(wchar_t wc) {
    if (wc >= 0x0041 && wc <= 0x005A) {
        return wc + (0x0061 - 0x0041);
    }

    return wc;
}

char x_toLowerA(char c) {
    if (c >= 0x41 && c <= 0x5A) {
        return c + (0x61 - 0x41);
    }

    return c;
}

wchar_t *x_wcsToLower(wchar_t *dst, wchar_t *src) {
    size_t len = x_wcslen(src);

    for (size_t i = 0; i < len; ++i) {
        dst[i] = x_toLowerW(src[i]);
    }

    dst[len] = 0x0000;
    return dst;
}

char *x_mbsToLower(char *dst, char *src) {
    size_t len = x_strlen(src);

    for (size_t i = 0; i < len; ++i) {
        dst[i] = x_toLowerA(S_CAST(UCHAR, src[i]));
    }

    dst[len] = 0x00;
    return dst;
}

size_t x_mbstowcs (wchar_t *dst, const char *src, size_t size) {

    int count = (int)size;
    while (--count >= 0) {
        if (!(*dst++ = *src++)) { return size - count - 1; }
    }

    return size - count;
}

size_t x_wcstombs (char *str, wchar_t *wcs, size_t size) {

    size_t count = 0;

    while (count < size) {
        if (*wcs > 255) {
            return (size_t) -1;
        }

        str[count] = (char)*wcs;
        if (*wcs++ == 0x0000) {
            break;
        }
        count++;
    }

    str[count] = 0;
    return count;
}

int x_mbsEndsWith (char *string, char *end) {

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

int x_wcsEndsWith (wchar_t *string, wchar_t *end) {

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

