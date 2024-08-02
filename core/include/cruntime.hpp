#ifndef HEXANE_CORELIB_MULTITOOL_HPP
#define HEXANE_CORELIB_MULTITOOL_HPP
#include <core/corelib.hpp>

FUNCTION void x_memcpy (void *dst, const void *src, size_t n);
FUNCTION void *x_memset (void *dst, int val, size_t len);
FUNCTION void x_strcpy (char *dst, char const *src);
FUNCTION size_t x_strncmp (char *str1, char *str2, size_t len);
FUNCTION int x_strcmp (char *str1, char *str2);
FUNCTION int x_memcmp (const void *str1, const void *str2, size_t count);
FUNCTION size_t x_strlen (const char* str);
FUNCTION size_t x_wcslen (const wchar_t *s);
FUNCTION char *x_strcat (char *str1, char *str2);
FUNCTION void x_wcscpy (wchar_t *dest, wchar_t const *src);
FUNCTION int x_wcscmp (wchar_t *str1, wchar_t *str2);
FUNCTION wchar_t *x_wcscat (wchar_t *str1, wchar_t *str2);
FUNCTION wchar_t x_toLowerW (wchar_t c);
FUNCTION char x_toLowerA (char c);
FUNCTION wchar_t *x_wcsToLower(wchar_t *dst, wchar_t *src);
FUNCTION char *x_mbsToLower(char *dst, char *src);
FUNCTION size_t x_mbstowcs (wchar_t *dst, const char *src, size_t size);
FUNCTION size_t x_wcstombs (char *str, wchar_t *wcs, size_t size);
FUNCTION int x_mbs_endswith (char *string, char *end);
FUNCTION int x_wcs_endswith (wchar_t *string, wchar_t *end);

#endif // HEXANE_CORELIB_MULTITOOL_HPP