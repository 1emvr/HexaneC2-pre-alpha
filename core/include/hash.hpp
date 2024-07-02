#ifndef HEXANE_HASH_HPP
#define HEXANE_HASH_HPP
#include <include/monolith.hpp>

#define FNV_OFFSET  (const unsigned int) 2166136261
#define FNV_PRIME	(const unsigned int) 16777619

#define NULTERM		0x00
#define WNULTERM 	0x00000000

DWORD GetHashFromStringA(PCHAR string, SIZE_T length);
DWORD GetHashFromStringW(PWCHAR string, SIZE_T length);

#endif // HEXANE_HASH_HPP
