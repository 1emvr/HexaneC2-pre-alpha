#ifndef HEXANE_CORELIB_CIPHER_HPP
#define HEXANE_CORELIB_CIPHER_HPP
#include <core/monolith.hpp>
#include <core/corelib.hpp>

#define FNV_OFFSET  (const unsigned int) 2166136261
#define FNV_PRIME	(const unsigned int) 16777619
#define XTEA_DELTA  (const unsigned int) 0x9E3779B9
#define NROUNDS     (const unsigned int) 64

struct U32_BLOCK {
    uint32_t v0;
    uint32_t v1;
};

struct CipherTxt {
    uint32_t table[64];
};

namespace Xtea {
    FUNCTION U32_BLOCK  BlockToUint32 (const byte *src);
    FUNCTION VOID       Uint32ToBlock (uint32_t v0, uint32_t v1, byte *dst) ;
    FUNCTION VOID       InitCipher (CipherTxt *c, const byte *m_key);
    FUNCTION VOID       XteaEncrypt(CipherTxt *c, byte *dst, byte *src);
    FUNCTION VOID       XteaDecrypt(CipherTxt *c, byte *dst, byte *src);
    FUNCTION PBYTE      *XteaDivide (byte *data, size_t cbData, size_t *cbOut);
    FUNCTION VOID       XteaCrypt(PBYTE data, SIZE_T cbData, PBYTE key, BOOL encrypt);
}
#endif //HEXANE_CORELIB_CIPHER_HPP
