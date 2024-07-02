#include "core/include/hash.hpp"
DWORD GetHashFromStringA(PCHAR string, SIZE_T length) {

    auto hash = FNV_OFFSET;

    if (string) {
        for (auto i = 0; i < length; i++) {
            hash ^= string[i];
            hash *= FNV_PRIME;
        }
    }
    return hash;
}

DWORD GetHashFromStringW(PWCHAR string, SIZE_T length) {

    auto hash = FNV_OFFSET;

    if (string) {
        for (auto i = 0; i < length; i++) {
            hash ^= string[i];
            hash *= FNV_PRIME;
        }
    }
    return hash;
}
