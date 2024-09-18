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
    FUNCTION VOID AppendPointerList(void **array[], void *pointer, uint32_t *count);
    FUNCTION ULONG HashStringA(char const *string, size_t length);
    FUNCTION ULONG HashStringW(wchar_t const *string, size_t length);

    namespace Scanners {
        FUNCTION BOOL MapScan(_hash_map* map, uint32_t id, void** pointer);
        FUNCTION BOOL SymbolScan(const char* string, const char symbol, size_t length);
        FUNCTION UINT_PTR RelocateExport(void* const process, const void* const target, size_t size);
        FUNCTION BOOL SigCompare(const uint8_t* data, const char* signature, const char* mask);
        FUNCTION UINT_PTR SignatureScan(void* process, const uintptr_t start, const uint32_t size, const char* signature, const char* mask);
    }

    namespace Time {
        FUNCTION ULONG64 GetTimeNow();
        FUNCTION BOOL InWorkingHours();
        FUNCTION VOID Timeout(size_t ms);
    }

    namespace Random {
        FUNCTION ULONG RandomSleepTime();
        FUNCTION ULONG RandomSeed();
        FUNCTION UINT_PTR Timestamp();
        FUNCTION ULONG RandomNumber32();
        FUNCTION BOOL RandomBool();
    }
}

#endif //HEXANE_CORELIB_UTILS_HPP
