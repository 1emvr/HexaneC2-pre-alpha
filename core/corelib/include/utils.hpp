#ifndef HEXANE_CORELIB_UTILS_HPP
#define HEXANE_CORELIB_UTILS_HPP
#include <monolith.hpp>
#include <core/corelib/corelib.hpp>

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

namespace Utils {
    FUNCTION ULONG64    GetTimeNow();
    FUNCTION BOOL       InWorkingHours();
    FUNCTION ULONG      GetHashFromStringW(LPWSTR String, SIZE_T Length);
    FUNCTION ULONG      GetHashFromStringA(LPSTR String, SIZE_T Length);

}

namespace Random {
    FUNCTION VOID       Timeout(size_t ms);
    FUNCTION UINT_PTR   Timestamp();
    FUNCTION ULONG      RandomNumber32();
    FUNCTION ULONG      RandomSleepTime();
    FUNCTION BOOL       RandomBool();
    FUNCTION INT        RandomSeed();
}
#endif //HEXANE_CORELIB_UTILS_HPP