#ifndef HEXANE_CORELIB_CIPHER_HPP
#define HEXANE_CORELIB_CIPHER_HPP

#define FNV_PRIME	(const unsigned int) 16777619
#define FNV_OFFSET  (const unsigned int) 2166136261
#define XTEA_DELTA  (const unsigned int) 0x9E3779B9
#define NROUNDS     (const unsigned int) 64

#include <core/corelib.hpp>

namespace Xtea {
    FUNCTION VOID Uint32ToBlock (uint32_t v0, uint32_t v1, uint8_t *dst) ;
    FUNCTION VOID InitCipher (_ciphertext *c, const uint8_t *m_key);
    FUNCTION VOID XteaEncrypt(_ciphertext *c, uint8_t *dst, uint8_t *src);
    FUNCTION VOID XteaDecrypt(_ciphertext *c, uint8_t *dst, uint8_t *src);
    FUNCTION PBYTE *XteaDivide (uint8_t *data, size_t n_data, size_t *n_out);
    FUNCTION VOID XteaCrypt(uint8_t *data, size_t n_data, uint8_t *m_key, bool encrypt);
}

#endif //HEXANE_CORELIB_CIPHER_HPP
