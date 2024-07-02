#ifndef HEXANE_HASH_HPP
#define HEXANE_HASH_HPP
#include <core/include/monolith.hpp>

#define FNV_OFFSET  (const unsigned int) 2166136261
#define FNV_PRIME	(const unsigned int) 16777619

#define WNULTERM 	0x00000000
#define NULTERM		0x00
#define PERIOD      0x2E
#define BSLASH      0x5C
#define ASTER       0x2A

FUNCTION ULONG GetHashFromStringA(PCHAR string, SIZE_T length);
FUNCTION ULONG GetHashFromStringW(PWCHAR string, SIZE_T length);

#endif // HEXANE_HASH_HPP
