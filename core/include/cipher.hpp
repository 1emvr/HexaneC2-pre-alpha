#ifndef HEXANE_CORELIB_CIPHER_HPP
#define HEXANE_CORELIB_CIPHER_HPP

#define FNV_PRIME	(const unsigned int) 16777619
#define FNV_OFFSET  (const unsigned int) 2166136261
#define XTEA_DELTA  (const unsigned int) 0x9E3779B9
#define NROUNDS     (const unsigned int) 64

#include <core/corelib.hpp>

namespace Xtea {
    typedef struct _CIPHERTEXT {
        DWORD table[64];
    } CIPHERTEXT, *PCIPHERTEXT;

    typedef struct _U32_BLOCK {
        UINT32 v0;
        UINT32 v1;
    } U32_BLOCK, *PU32_BLOCK;

    VOID Uint32ToBlock(UINT32 v0, UINT32 v1, UINT8 *dst);
    VOID InitCipher(CIPHERTEXT *c, CONST UINT8 *mKey);
    VOID XteaEncrypt(CONST CIPHERTEXT *c, UINT8 *dst, CONST UINT8 *src);
    VOID XteaDecrypt(CONST CIPHERTEXT *c, UINT8 *dst, CONST UINT8 *src);
    VOID XteaCrypt(UINT8 *data, SIZE_T nData, UINT8* mKey, BOOL Encrypt);
    UINT8** XteaDivide (CONST UINT8 *Data, SIZE_T nData, SIZE_T *nOut);
}

namespace Hash {
    ULONG LdrHashEntry(UNICODE_STRING uniName, BOOL xorHash);
    UINT32 HashStringA(CHAR CONST *string, SIZE_T length);
    UINT32 HashStringW(WCHAR CONST *string, SIZE_T length);
}
#endif //HEXANE_CORELIB_CIPHER_HPP
