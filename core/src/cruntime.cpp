#include <core/include/cruntime.hpp>

#define NULTERM 0x00
#define WNULTERM 0x00000000

void x_memcpy (void *dst, const void *src, size_t n) {

    auto a = SCAST(uint8_t*, dst);
    auto b = SCAST(const uint8_t*, src);

    for (size_t i = 0; i < n; i++) {
        a[i] = b[i];
    }
}

void *x_memset (void *dst, int val, size_t len) {

    auto *ptr = SCAST(uint8_t*, dst);
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

    const auto *s1 = SCAST(const uint8_t*, str1);
    const auto *s2 = SCAST(const uint8_t*, str2);

    while (count-- > 0) {

        if (*s1++ != *s2++) {
            return s1[-1] < s2[-1] ? -1 : 1;
        }
    }

    return 0;
}


size_t x_strlen (const char* str) {

    const char* char_ptr    = { };
    const uint32_t* u32ptr  = { };

    uint32_t longword = 0, himagic = 0, lomagic = 0;

    for (char_ptr = str; (RCAST(UINT_PTR, char_ptr) & (sizeof(longword) - 1)) != NULTERM; ++char_ptr ) {
        if ( *char_ptr == NULTERM ) {
            return char_ptr - str;
        }
    }

    u32ptr 	= (uint32_t*) char_ptr;
    himagic 		= 0x80808080L;
    lomagic 		= 0x01010101L;

    if (sizeof(longword) > 4) {
        himagic = himagic << 16 << 16 | himagic;
        lomagic = lomagic << 16 << 16 | lomagic;
    }
    if ( sizeof(longword) > 8 ) {
        return 0;
    }

    for (;;) {

        longword = *u32ptr++;
        if ((longword - lomagic & ~longword & himagic) != 0 ) {

            auto cp = (char*)u32ptr - 1;
            if (cp[0] == 0)
                return cp - str;
            if (cp[1] == 0)
                return cp - str + 1;
            if (cp[2] == 0)
                return cp - str + 2;
            if (cp[3] == 0)
                return cp - str + 3;
            if (sizeof(longword) > 4) {
                if (cp[4] == 0)
                    return cp - str + 4;
                if (cp[5] == 0)
                    return cp - str + 5;
                if (cp[6] == 0)
                    return cp - str + 6;
                if (cp[7] == 0)
                    return cp - str + 7;
            }
        }
    }
}

char *x_strcat (char *str1, char *str2) {

    x_strcpy(str1 + x_strlen(str1), str2);
    return str1;
}

size_t x_wcslen (const wchar_t *s) {

    size_t len = 0;
    while (s[ len] != WNULTERM ) {
        if (s[++len] == WNULTERM)
            return len;
        if (s[++len] == WNULTERM)
            return len;
        if (s[++len] == WNULTERM)
            return len;
        ++len;
    }

    return len;
}

void x_wcscpy (wchar_t *dest, wchar_t const *src) {

    while ((*dest = *src) != WNULTERM) {
        dest++;
        src++;
    }
}

int x_wcscmp (wchar_t *str1, wchar_t *str2) {

    for (; *str1 == *str2; str1++, str2++) {
        if (*str1 == WNULTERM) {
            return 0;
        }
    }
    return *SCAST(wchar_t*, str1) < *SCAST(wchar_t*, str2) ? -1 : +1;
}

wchar_t *x_wcscat (wchar_t *str1, wchar_t *str2) {

    x_wcscpy(str1 + x_wcslen(str1), str2 );
    return str1;
}

wchar_t x_toLowerW (wchar_t c) {
    return c > 0x40 && c < 0x5B ? c | 0x60 : c;
}

unsigned char x_toLowerA(unsigned char c) {
    return c >= 0x41 && c <= 0x5A ? c | 0x20 : c;
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
        if (*wcs++ == WNULTERM) {
            break;
        }
        count++;
    }

    str[count] = 0;
    return count;
}

int x_mbs_endswith (char *string, char *end) {

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

int x_wcs_endswith (wchar_t *string, wchar_t *end) {

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

