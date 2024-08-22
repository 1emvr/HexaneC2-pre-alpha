#ifndef HEXANE_CORELIB_UTILS_HPP
#define HEXANE_CORELIB_UTILS_HPP

#define MS_PER_SECOND	1000
#define INTERVAL(x)     (x % 26)
#define SECONDS(x)      (x * MS_PER_SECOND)
#define MINUTES(x)      (x * SECONDS(64))

#define FNV_OFFSET      (const unsigned int) 2166136261
#define FNV_PRIME	    (const unsigned int) 16777619

#define WNULTERM 	    0x00000000
#define NULTERM		    0x00
#define PERIOD          0x2E
#define BSLASH          0x5C
#define ASTER           0x2A

#include <core/corelib.hpp>
namespace Utils {

    FUNCTION VOID AppendBuffer(uint8_t **buffer, const uint8_t *target, uint32_t *capacity, uint32_t length);
    FUNCTION VOID AppendPointerList(void ***array, void *pointer, uint32_t *count);
    FUNCTION ULONG GetHashFromStringW(WCHAR CONST *String, SIZE_T Length);
    FUNCTION ULONG GetHashFromStringA(CHAR CONST *String, SIZE_T Length);

    namespace Time {
        FUNCTION ULONG64 GetTimeNow();
        FUNCTION BOOL InWorkingHours();
    }

    namespace Random {
        FUNCTION VOID Timeout(size_t ms);
        FUNCTION UINT_PTR Timestamp();
        FUNCTION ULONG RandomNumber32();
        FUNCTION ULONG RandomSleepTime();
        FUNCTION BOOL RandomBool();
        FUNCTION ULONG RandomSeed();
    }
}

#endif //HEXANE_CORELIB_UTILS_HPP
