#ifndef _HEXANE_MULTITOOL_HPP
#define _HEXANE_MULTITOOL_HPP
#include <core/include/monolith.hpp>

void x_memcpy (void *dst, const void *src, size_t n);
void *x_memset (void *dst, int val, size_t len);
void x_strcpy (char *dst, char const *src);
int x_strncmp (char *str1, char *str2, size_t len);
int x_strcmp (char *str1, char *str2);
int x_memcmp (const void *str1, const void *str2, size_t count);
size_t x_strlen (const char *str);
char *x_strcat (char *str1, char *str2);
size_t x_wcslen (const wchar_t *s);
void x_wcscpy (wchar_t *dest, wchar_t const *src);
int x_wcscmp (wchar_t *str1, wchar_t *str2);
wchar_t *x_wcscat (wchar_t *str1, wchar_t *str2);
wchar_t x_toLowerW (wchar_t c);
size_t x_mbstowcs (wchar_t *dst, char *src, size_t size);
size_t x_wcstombs (char *str, wchar_t *wcs, size_t size);
int x_mbs_endswith (char *string, char *end);
int x_wcs_endswith (wchar_t *string, wchar_t *end);
#endif // _HEXANE_MULTITOOL_HPP