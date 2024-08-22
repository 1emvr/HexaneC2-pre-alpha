#include <core/include/cipher.hpp>
namespace Xtea {

    VOID Uint32ToBlock (const uint32_t v0, const uint32_t v1, uint8_t *dst)  {

        dst[0] = v0 >> 24; dst[1] = v0 >> 16; dst[2] = v0 >> 8; dst[3] = v0;
        dst[4] = v1 >> 24; dst[5] = v1 >> 16; dst[6] = v1 >> 8;
        dst[7] = v1;
    }

    VOID InitCipher (_ciphertext *const c, const uint8_t *const m_key) {

        uint32_t key[4] = { };
        uint32_t sum    = { };

        auto delta = XTEA_DELTA;

        for (uint32_t i = 0; i < ARRAY_LEN(key); i++) {
            uint32_t j = i << 2;

            key[i] =
                S_CAST(uint32_t, m_key[j+0]) << 24 |
                S_CAST(uint32_t, m_key[j+1]) << 16 |
                S_CAST(uint32_t, m_key[j+2]) << 8  |
                S_CAST(uint32_t, m_key[j+3]);
        }

        for (uint32_t i = 0; i < NROUNDS;) {
            c->table[i] = sum + key[sum & 3];
            i++;

            sum += delta;
            c->table[i] = sum + key[sum >> 11 & 3];
            i++;
        }
    }

    VOID XteaEncrypt(const _ciphertext *const c, uint8_t *const dst, const uint8_t *const src) {

        _u32_block block = {
            block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3],
            block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7],
        };

        for (auto i = 0; i < NROUNDS;) {
            block.v0 += (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ c->table[i];
            i++;

            block.v1 += (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ c->table[i];
            i++;
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    VOID XteaDecrypt(const _ciphertext *const c, uint8_t *const dst, const uint8_t *const src) {

        _u32_block block = {
            block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3],
            block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7],
        };

        for (auto i = NROUNDS; i > 0;) {
            i--;
            block.v1 -= (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ c->table[i];

            i--;
            block.v0 -= (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ c->table[i];
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    PBYTE *XteaDivide (const uint8_t *const data, const size_t n_data, size_t *const n_out) {
        HEXANE

        uint8_t **sections = { };
        constexpr auto sec_size  = 8;
        const auto n = (n_data + sec_size - 1) / sec_size;

        *n_out = n;

        if (!(sections = S_CAST(uint8_t**, x_malloc(n * sizeof(uint8_t*))))) {
            return nullptr;
        }
        for (size_t i = 0; i < n; i++) {
            if (!(sections[i] = B_PTR(x_malloc(sec_size)))) {

                for (auto j = 0; j < i; j++) {
                    x_free(sections[j]);
                }

                x_free(sections);
                return_defer(ERROR_NOT_ENOUGH_MEMORY);
            }

            const auto end = (i + 1) * sec_size;
            const auto copy_size = (end > n_data) ? n_data - i * sec_size : sec_size;

            x_memcpy(sections[i], data + i * sec_size, copy_size);

            if (copy_size < sec_size) {
                x_memset(sections[i] + copy_size, 0, sec_size - copy_size);
            }
        }

        defer:
        return sections;
    }

    VOID XteaCrypt(uint8_t *const data, const size_t n_data, uint8_t *const m_key, const bool encrypt) {
        HEXANE

        _ciphertext *text = { };
        uint8_t **sections = { };
        uint8_t *buffer = { };
        uint8_t *key = { };

        int32_t offset = 0;
        size_t n_sect = { };

        if (!m_key) {
            key = Ctx->config.key;
        } else {
            key = m_key;
        }

        if (!(text = S_CAST(_ciphertext*, x_malloc(sizeof(_ciphertext))))) {
            return;
        }
        InitCipher(text, key);

        if (!(sections = XteaDivide(data, n_data, &n_sect))) {
            return;
        }

        x_memset(data, 0, n_data);

        for (auto i = 0; i < n_sect; i++) {
            if (!(buffer = B_PTR(x_malloc(8)))) {
                return;
            }
            if (encrypt) {
                XteaEncrypt(text, buffer, sections[i]);
            } else {
                XteaDecrypt(text, buffer, sections[i]);
            }

            x_memcpy(C_PTR(data+offset), C_PTR(buffer), sizeof(uint64_t));

            x_free(buffer);
            offset += sizeof(uint64_t);
        }

        for (uint64_t i = 0; i < n_sect; i++) {
            x_free(sections[i]);
        }

        x_free(sections);
        x_free(text);
    }
}
