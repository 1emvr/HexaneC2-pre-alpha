#include <core/include/stdlib.hpp>
void MemCopy (void *dst, const void *const src, const size_t n) {

    const auto a = (uint8*) dst;
    const auto b = (const uint8*) src;

    for (size_t i = 0; i < n; i++) {
        a[i] = b[i];
    }
}

void *MemSet (void *const dst, const int val, size_t len) {

    auto ptr = (uint8*) dst;
    while (len-- > 0) {
        *ptr++ = val;
    }
    return dst;
}

char* MbsCopy(char *dst, const char *src, size_t n) {

    if (!n) {
        return dst;
    }

    char *d = dst;
    size_t copied = 0;

    while (copied < n - 1 && *src) {
        *d++ = *src++;
        copied++;
    }

    *d++ = '\0';
    copied++;

    while (copied < n) {
        *d++ = '\0';
        copied++;
    }

    return dst;
}

size_t MbsBoundCompare(const char *str1, const char *str2, size_t len) {

    while (len && *str1 && (*str1 == *str2)) {
        len--; str1++; str2++;

        if (len == 0) {
            return  0;
        }
    }
    return len ? (unsigned char)*str1 - (unsigned char)*str2 : 0;
}


size_t MbsCompare (const char *str1, const char *str2) {

    while (*str1 && *str1 == *str2) {
        str1++; str2++;
    }

    return (uint8) *str1 - (uint8) *str2;
}

size_t MemCompare (const void *const ptr1, const void *const ptr2, size_t len) {

    const auto *p1 = (const uint8*) ptr1;
    const auto *p2 = (const uint8*) ptr2;

    while (len--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }

        p1++; p2++;
    }

    return 0;
}

char *MbsConcat (char *const dst, const char *const src) {

    size_t len1 = strlen(dst);
    MbsCopy(dst + len1, src, len1);
    return dst;
}

size_t MbsLength (const char* str) {

    auto len = 0;
    const auto s_str = str;

    while (s_str[len] != 0x00) {
        len++;
    }

    return len;
}

size_t WcsLength (const wchar_t *const s) {

    size_t len = 0;
    const auto s_str = s;

    while (s_str[len] != 0x0000) {
        len++;
    }

    return len;
}

wchar_t* WcsCopy(wchar_t *dst, const wchar_t *src, size_t n) {

    if (!n) {
        return dst;
    }

    wchar_t *d      = dst;
    size_t copied   = 0;

    while (copied < n - 1 && *src) {
        *d++ = *src++;
        copied++;
    }

    *d++ = L'\0';
    copied++;

    while (copied < n) {
        *d++ = L'\0';
        copied++;
    }

    return dst;
}

size_t WcsCompare (const wchar_t *str1, const wchar_t *str2) {

    for (; *str1 == *str2; str1++, str2++) {
        if (*str1 == 0x0000) {
            return 0;
        }
    }
    return *str1 < *str2 ? -1 : +1;
}

wchar_t *WcsConcat (wchar_t *const str1, const wchar_t *const str2) {

    size_t len1 = WcsLength(str1);
    WcsCopy(str1 + len1, str2, len1);
    return str1;
}

wchar_t ToLowerW(const wchar_t c) {
    if (c >= 0x0041 && c <= 0x005A) {
        return c + (0x0061 - 0x0041);
    }

    return c;
}

char ToLowerA(const char c) {
    if (c >= 0x41 && c <= 0x5A) {
        return c + (0x61 - 0x41);
    }

    return c;
}

wchar_t *WcsToLower(wchar_t *const dst, const wchar_t *const src) {

    const auto len = WcsLength(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = ToLowerW(src[i]);
    }

    dst[len] = 0x0000;
    return dst;
}

char *MbsToLower(char *const dst, const char *const src) {

    const auto len = MbsLength(src);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = ToLowerA((uint8) src[i]);
    }

    dst[len] = 0x00;
    return dst;
}

size_t MbsToWcs (wchar_t *dst, const char *src, const size_t size) {

    auto count = size;
    while (--count) {
        if (!(*dst++ = *src++)) {
            return size - count - 1;
        }
    }

    return size - count;
}

size_t WcsToMbs (char *const str, const wchar_t *wcs, size_t size) {

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

int MbsEndsWith (const char *string, const char *const end) {

    uint32_t length1 = 0;
    uint32_t length2 = 0;

    if (!string || !end) {
        return false;
    }

    length1 = MbsLength(string);
    length2 = MbsLength(end);

    if (length1 < length2) {
        return false;
    }
    string = &string[length1 - length2];
    return MbsCompare(string, end) == 0;
}

int WcsEndsWith (const wchar_t *string, const wchar_t *const end) {

    uint32_t length1 = 0;
    uint32_t length2 = 0;

    if ( !string || !end ) {
        return false;
    }

    length1 = WcsLength(string);
    length2 = WcsLength(end);

    if ( length1 < length2 ) {
        return false;
    }

    string = &string[ length1 - length2 ];
    return WcsCompare(string, end) == 0;
}

size_t MbsSpan(const char* s, const char* accept) {

    int a = 1;
    int i;

    size_t offset = 0;

    while (a && *s) {
        for (a = i = 0; !a && i < MbsLength(accept); i++) {
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

char* MbsChar(const char* str, int c) {

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

char* MbsToken(char* str, const char* delim) {

    static char *saved          = { };
    char        *token_start    = { };
    char        *token_end      = { };

    if (str) { saved = str; }
    token_start = saved;

    if (!token_start) {
        saved = nullptr;
        return nullptr;
    }

    while (*token_start && MbsChar(delim, *token_start)) {
        token_start++;
    }

    token_end = token_start;
    while (*token_end && !MbsChar(delim, *token_end)) {
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

char* MbsDuplicate(const char* str) {
    HEXANE;

    char*   str2      = { };
    size_t  length  = 0;

    length  = MbsLength(str);
    str2    = (char*) Malloc(length + 1);

    if (!str2) {
        return nullptr;
    }

    MemCopy(str2, str, length + 1);
    return str2;
}

char** NewSplit(const char* str, const char* delim, int* count) {
    HEXANE;

    char **result   = { };
    char **temp_res = { };

    char *temp      = { };
    char *token     = { };

    int size    = 2;
    int index   = 0;

    x_assert(temp   = MbsDuplicate(str));
    x_assert(result = (char**) Malloc(size * sizeof(char*)));
    x_assert(token  = MbsToken(temp, delim));

    while (token) {
        if (index > size) {
            size    += 1;
            temp_res = (char**) Realloc(result, size * sizeof(char*));

            if (!temp_res) {
                Free(result);
                result = nullptr;

                goto defer;
            }

            result = temp_res;
        }

        result[index] = MbsDuplicate(token);

        if (!result[index]) {
            for (auto i = 0; i < index; i++) {
                Free(result[i]);
            }

            Free(result);
            result = nullptr;

            goto defer;
        }

        index++;
        token = MbsToken(0, delim);
    }

    *count = index;
    result[index] = 0;

    defer:
    Free(temp);
    return result;
}

void FreeSplit(char** split, int count) {
    HEXANE;

    for (auto i = 0; i < count; i++) {
        Free(split[i]);
    }

    Free(split);
}

void Trim(char* str, char delim) {

    for (auto i = 0; str[i]; i++) {
        if (str[i] == delim) {
            str[i] = 0;
        }
    }
}

BOOL StringChar(const char* string, const char symbol, size_t length) {
    for (auto i = 0; i < length - 1; i++) {
        if (string[i] == symbol) {
            return true;
        }
    }

    return false;
}
