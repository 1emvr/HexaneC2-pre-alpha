#ifndef HEXANE_CORELIB_CIPHER_HPP
#define HEXANE_CORELIB_CIPHER_HPP

#define FNV_PRIME	(const unsigned int) 16777619
#define FNV_OFFSET  (const unsigned int) 2166136261
#define XTEA_DELTA  (const unsigned int) 0x9E3779B9
#define NROUNDS     (const unsigned int) 64

#include <core/corelib.hpp>

namespace Xtea {
    VOID
    FUNCTION
        Uint32ToBlock(UINT32 v0, UINT32 v1, UINT8 *dst);

    VOID
    FUNCTION
        InitCipher(CIPHERTEXT *c, CONST UINT8 *m_key);

    VOID
    FUNCTION
        XteaEncrypt(CONST CIPHERTEXT *c, UINT8 *dst, CONST UINT8 *src);

    VOID
    FUNCTION
        XteaDecrypt(CONST CIPHERTEXT *c, UINT8 *dst, CONST UINT8 *src);

    VOID
    FUNCTION
        XteaCrypt(UINT8 *data, SIZE_T nData, UINT8* mKey, BOOL Encrypt);

    UINT8**
    FUNCTION
        XteaDivide (CONST UINT8 *Data, SIZE_T nData, SIZE_T *nOut);
}

#endif //HEXANE_CORELIB_CIPHER_HPP
