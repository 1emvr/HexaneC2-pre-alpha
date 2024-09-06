#include <core/include/stdlib.hpp>
void x_memcpy (void *dst, const void *const src, const size_t n) {

    const auto a = (uint8_t*) dst;
    const auto b = (const uint8_t*) src;

    for (size_t i = 0; i < n; i++) {
        a[i] = b[i];
    }
}

void *x_memset (void *const dst, const int val, size_t len) {

    auto ptr = (uint8_t*) dst;
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

    return (uint8_t) *str1 - (uint8_t) *str2;
}

int x_memcmp (const void *const ptr1, const void *const ptr2, size_t len) {

    const auto *p1 = (const uint8_t*) ptr1;
    const auto *p2 = (const uint8_t*) ptr2;

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

    while (s_str[len] != 0x0000) {
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
        dst[i] = x_toLowerA((uint8_t) src[i]);
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

size_t x_strspn(const char* s, const char* accept) {

    int a = 1;
    int i;

    size_t offset = 0;

    while (a && *s) {
        for (a = i = 0; !a && i < x_strlen(accept); i++) {
            if (*s == accept[i]) {
                a = 1;
            }
        }

        if (a) {
            offset++;
        }
        s++;
    }

    return offset;
}

char* x_strchr(const char* str, int c) {

    while (*str) {
        if (*str == (char)c) {
            return (char*) str;
        }
        str++;
    }

    if (c == 0) {
        return (char*)str;
    }

    return nullptr;
}

char* x_strtok(char* str, const char* delim) {

    static char *saved          = { };
    char        *token_start    = { };
    char        *token_end      = { };

    if (str) { saved = str; }
    token_start = saved;

    if (!token_start) {
        saved = nullptr;
        return nullptr;
    }

    while (*token_start && x_strchr(delim, *token_start)) {
        token_start++;
    }

    token_end = token_start;
    while (*token_end && !x_strchr(delim, *token_end)) {
        token_end++;
    }

    if (*token_end) {
        *token_end  = 0;
        saved       = token_end + 1;
    }
    else {
        saved = nullptr;
    }

    return token_start;
}

char* x_strdup(const char* str) {

    char*   str2      = { };
    size_t  length  = 0;

    length  = x_strlen(str);
    str2    = (char*) x_malloc(length + 1);

    if (!str2) {
        return nullptr;
    }

    x_memcpy(str2, str, length + 1);
    return str2;
}

char** x_split(const char* str, const char* delim, int* count) {

    char **result   = { };
    char **temp_res = { };

    char *temp      = { };
    char *token     = { };

    int size    = 2;
    int index   = 0;

    x_assert(temp   = x_strdup(str));
    x_assert(result = (char**) x_malloc(size * sizeof(char*)));
    x_assert(token  = x_strtok(temp, delim));

    while (token) {
        if (index > size) {
            size    += 1;
            temp_res = (char**) x_realloc(result, size * sizeof(char*));

            if (!temp_res) {
                x_free(result);
                result = nullptr;

                goto defer;
            }

            result = temp_res;
        }

        result[index] = x_strdup(token);

        if (!result[index]) {
            for (auto i = 0; i < index; i++) {
                x_free(result[i]);
            }

            x_free(result);
            result = nullptr;

            goto defer;
        }

        index++;
        token = x_strtok(0, delim);
    }

    *count = index;
    result[index] = 0;

    defer:
    x_free(temp);
    return result;
}

void x_freesplit(char** split, int count) {

    for (auto i = 0; i < count; i++) {
        x_free(split[i]);
    }

    x_free(split);
}

void x_trim(char* str, char delim) {

    for (auto i = 0; str[i]; i++) {
        if (str[i] == delim) {
            str[i] = 0;
        }
    }
}