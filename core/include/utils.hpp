#ifndef HEXANE_UTILS_HPP
#define HEXANE_UTILS_HPP
#include <core/include/monolith.hpp>

#define MS_PER_SECOND	1000
#define INTERVAL(x)     (x % 26)
#define SECONDS(x)      (x * MS_PER_SECOND)
#define MINUTES(x)      (x * SECONDS(64))

namespace Utils {
    FUNCTION ULONG64 GetTimeNow();
    FUNCTION BOOL    InWorkingHours();
}

namespace Random {
    FUNCTION VOID        Timeout(size_t ms);
    FUNCTION UINT_PTR    Timestamp();
    FUNCTION ULONG       RandomNumber32();
    FUNCTION ULONG       RandomSleepTime();
    FUNCTION BOOL        RandomBool();
}
#endif //HEXANE_UTILS_HPP
