#include <core/include/hash.hpp>
ULONG GetHashFromStringA(PCHAR string, SIZE_T length) {

    auto hash = FNV_OFFSET;

    if (string) {
        for (auto i = 0; i < length; i++) {
            hash ^= string[i];
            hash *= FNV_PRIME;
        }
    }
    return hash;
}

ULONG GetHashFromStringW(PWCHAR string, SIZE_T length) {

    auto hash = FNV_OFFSET;

    if (string) {
        for (auto i = 0; i < length; i++) {
            hash ^= string[i];
            hash *= FNV_PRIME;
        }
    }
    return hash;
}
