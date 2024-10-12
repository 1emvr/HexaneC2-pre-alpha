#ifndef HEXANE_CORELIB_MULTITOOL_HPP
#define HEXANE_CORELIB_MULTITOOL_HPP
#include <core/corelib.hpp>

VOID
FUNCTION
    MemCopy(VOID *dst, CONST VOID *src, SIZE_T n);

PVOID
FUNCTION
    MemSet(VOID *dst, INT val, SIZE_T len);

SIZE_T
FUNCTION
    MemCompare(CONST VOID *ptr1, CONST VOID *ptr2, SIZE_T len);

VOID
FUNCTION
    MbsCopy(CHAR *dst, CONST CHAR *src);

SIZE_T
FUNCTION
    MbsBoundCompare(CONST CHAR *str1, CONST CHAR *str2, SIZE_T len);

SIZE_T
FUNCTION
    MbsCompare(CONST CHAR *str1, CONST CHAR *str2);

LPSTR
FUNCTION
    MbsConcat(CHAR *str1, CONST CHAR *str2);

SIZE_T
FUNCTION
    MbsLength(CONST CHAR* str);

SIZE_T
FUNCTION
    WcsLength(CONST WCHAR *s);

VOID
FUNCTION
    WcsCopy(WCHAR *dest, CONST WCHAR *src);

SIZE_T
FUNCTION
    WcsCompare(CONST WCHAR *str1, CONST WCHAR *str2);

LPWSTR
FUNCTION
    WcsConcat(WCHAR *str1, CONST WCHAR *str2);

WCHAR
FUNCTION
    ToLowerW(WCHAR c);

CHAR
FUNCTION
    ToLowerA(CHAR c);

LPWSTR
FUNCTION
    WcsToLower(WCHAR *dst, CONST WCHAR *src);

PCHAR
FUNCTION
    MbsToLower(CHAR *dst, CONST CHAR *src);

SIZE_T
FUNCTION
    MbsToWcs(WCHAR *dst, CONST CHAR *src, SIZE_T size);

SIZE_T
FUNCTION
    WcsToMbs(CHAR *str, CONST WCHAR *wcs, SIZE_T size);

SIZE_T
FUNCTION
    MbsEndsWith(CONST CHAR *string, CONST CHAR *end);

SIZE_T
FUNCTION
    WcsEndsWith(CONST WCHAR *string, CONST WCHAR *end);

SIZE_T
FUNCTION
    MbsSpan(CONST CHAR *s, CONST CHAR* accept);

LPSTR
FUNCTION
    SubChar(CONST CHAR *str, INT c);

LPSTR
FUNCTION
    MbsToken(CHAR *str, CONST CHAR *delim);

LPSTR
FUNCTION
    MbsDuplicate(CONST CHAR *str);

LPSTR*
FUNCTION
    AllocSplit(CONST CHAR *str, CONST CHAR *delim, INT *count);

VOID
FUNCTION
    FreeSplit(CHAR **split, INT count);

VOID
FUNCTION
    Trim(CHAR *str, CHAR delim);


#endif // HEXANE_CORELIB_MULTITOOL_HPP
