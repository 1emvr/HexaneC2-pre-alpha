#ifndef HEXANE_CORELIB_CIPHER_HPP
#define HEXANE_CORELIB_CIPHER_HPP

#define FNV_PRIME	(const unsigned int) 16777619
#define FNV_OFFSET  (const unsigned int) 2166136261
#define XTEA_DELTA  (const unsigned int) 0x9E3779B9
#define NROUNDS     (const unsigned int) 64
#include <core/corelib.hpp>

namespace Xtea {

    FUNCTION _u32_block BlockToUint32 (uint8_t const *src);
    FUNCTION VOID Uint32ToBlock (uint32_t v0, uint32_t v1, uint8_t *dst) ;
    FUNCTION VOID InitCipher (_ciphertext *c, uint8_t *m_key);
    FUNCTION VOID XteaEncrypt(_ciphertext *c, uint8_t *dst, uint8_t *src);
    FUNCTION VOID XteaDecrypt(_ciphertext *c, uint8_t *dst, uint8_t *src);
    FUNCTION VOID XteaCrypt(uint8_t *data, size_t cbData, uint8_t *key, bool encrypt);
    FUNCTION PBYTE* XteaDivide (uint8_t *data, size_t cbData, size_t *cbOut);
}

template <uint32_t N>
struct obfuscator {
    char m_data[N] = { };

    constexpr explicit obfuscator(const char* data) {
        for (auto i = 0; i < N; i++) {
            m_data[i] = data[i] ^ 0x0A;
        }
    }

    void deobfuscate(unsigned char *dst) const {
        int i = 0;
        do {
            dst[i] = m_data[i] ^ 0x0A;
        } while (dst[i - 1]);
    }
};

template <uint32_t N>
struct obfuscatorw {
    wchar_t m_data[N] = { };

    constexpr explicit obfuscatorw(const wchar_t* data) {
        for (auto i = 0; i < N; i++) {
            m_data[i] = data[i] ^ 0x0A;
        }
    }

    void deobfuscate(wchar_t *dst) const {
        int i = 0;
        do {
            dst[i] = m_data[i] ^ 0x0A;
        } while (dst[i - 1]);
    }
};

#define OBF(str)                                    \
    []() -> char* {                                 \
        constexpr auto size = ARRAY_LEN(str);       \
        constexpr auto obf = obfuscator<size>(str); \
        static char original[size];                 \
                                                    \
        obf.deobfuscate((unsigned char*)original);  \
        return original;                            \
}()

#define OBFW(str)                                       \
    []() -> wchar_t* {                                  \
        constexpr auto size = ARRAY_LEN(str);           \
        constexpr auto obf = obfuscatorw<size>(str);    \
        static wchar_t original[size];                  \
                                                        \
        obf.deobfuscate((wchar_t*)original);            \
        return original;                                \
}()
#endif //HEXANE_CORELIB_CIPHER_HPP
