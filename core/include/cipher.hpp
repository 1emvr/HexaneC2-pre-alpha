#ifndef HEXANE_CORELIB_CIPHER_HPP
#define HEXANE_CORELIB_CIPHER_HPP

#define FNV_PRIME	(const unsigned int) 16777619
#define FNV_OFFSET  (const unsigned int) 2166136261
#define XTEA_DELTA  (const unsigned int) 0x9E3779B9
#define NROUNDS     (const unsigned int) 64

#include <core/corelib.hpp>

namespace Xtea {
    FUNCTION VOID Uint32ToBlock (const uint32_t v0, const uint32_t v1, uint8_t *dst) ;
    FUNCTION VOID InitCipher (_ciphertext *const c, const uint8_t *const m_key);
    FUNCTION VOID XteaEncrypt(const _ciphertext *const c, uint8_t *const dst, const uint8_t *const src);
    FUNCTION VOID XteaDecrypt(const _ciphertext *const c, uint8_t *const dst, const uint8_t *const src);
    FUNCTION PBYTE *XteaDivide (const uint8_t *const data, const size_t n_data, size_t *const n_out);
    FUNCTION VOID XteaCrypt(uint8_t *const data, const size_t n_data, uint8_t *const m_key, const bool encrypt);
}

#endif //HEXANE_CORELIB_CIPHER_HPP
