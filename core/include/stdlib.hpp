#ifndef HEXANE_CORELIB_MULTITOOL_HPP
#define HEXANE_CORELIB_MULTITOOL_HPP
#include <core/corelib.hpp>

FUNCTION void x_memcpy (void *dst, const void *const src, const size_t n);
FUNCTION void *x_memset (void *const dst, const int val, size_t len);
FUNCTION void x_strcpy (char *dst, const char *src);
FUNCTION size_t x_strncmp (const char *str1, const char *str2, size_t len);
FUNCTION int x_strcmp (const char *str1, const char *str2);
FUNCTION int x_memcmp (const void *const ptr1, const void *const ptr2, size_t len);
FUNCTION char *x_strcat (char *const str1, const char *const str2);
FUNCTION size_t x_strlen (const char* str);
FUNCTION size_t x_wcslen (const wchar_t *const s);
FUNCTION void x_wcscpy (wchar_t *dest, const wchar_t *src);
FUNCTION int x_wcscmp (const wchar_t *str1, const wchar_t *str2);
FUNCTION wchar_t *x_wcscat (wchar_t *const str1, const wchar_t *const str2);
FUNCTION wchar_t x_tolower_w(const wchar_t c);
FUNCTION char x_tolower_a(const char c);
FUNCTION wchar_t *x_wcs_tolower(wchar_t *const dst, const wchar_t *const src);
FUNCTION char *x_mbs_tolower(char *const dst, const char *const src);
FUNCTION size_t x_mbstowcs (wchar_t *dst, const char *src, const size_t size);
FUNCTION size_t x_wcstombs (char *const str, const wchar_t *wcs, size_t size);
FUNCTION int x_mbs_endswith (const char *string, const char *const end);
FUNCTION int x_wcs_endswith (const wchar_t *string, const wchar_t *const end);
FUNCTION size_t x_strspn(const char* s, const char* accept);
FUNCTION char* x_strchr(const char* str, int c);
FUNCTION char* x_strtok(char* str, const char* delim);
FUNCTION char* x_strdup(const char* str);
FUNCTION char** x_split(const char* str, const char* delim, int* count);
FUNCTION void x_freesplit(char** split, int count);
FUNCTION void x_trim(char* str, char delim);

#endif // HEXANE_CORELIB_MULTITOOL_HPP
