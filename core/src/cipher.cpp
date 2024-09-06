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

        for (uint32_t key_index = 0; key_index < ARRAY_LEN(key); key_index++) {
            uint32_t m_index = key_index << 2;

            key[key_index] = (uint32_t) m_key[m_index+0] << 24 | (uint32_t) m_key[m_index+1] << 16 | (uint32_t) m_key[m_index+2] << 8  | (uint32_t) m_key[m_index+3];
        }

        for (uint32_t blk_index = 0; blk_index < NROUNDS;) {
            c->table[blk_index] = sum + key[sum & 3];
            blk_index++;

            sum += delta;
            c->table[blk_index] = sum + key[sum >> 11 & 3];
            blk_index++;
        }
    }

    VOID XteaEncrypt(const _ciphertext *const c, uint8_t *const dst, const uint8_t *const src) {

        _u32_block block = {
            block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3],
            block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7],
        };

        for (auto i = 0; i < NROUNDS;) {
            block.v0 += (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ c->table[i]; i++;
            block.v1 += (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ c->table[i]; i++;
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    VOID XteaDecrypt(const _ciphertext *const c, uint8_t *const dst, const uint8_t *const src) {

        _u32_block block = {
            block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3],
            block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7],
        };

        for (auto i = NROUNDS; i > 0;) {
            i--; block.v1 -= (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ c->table[i];
            i--; block.v0 -= (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ c->table[i];
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    PBYTE *XteaDivide (const uint8_t *const data, const size_t n_data, size_t *const n_out) {

        uint8_t         **sections  = { };
        constexpr auto  sec_size    = 8;
        const auto      n_sec       = (n_data + sec_size - 1) / sec_size;

        *n_out = n_sec;
        x_assert(sections = (uint8_t**) x_malloc(n_sec * sizeof(uint8_t*)));

        for (auto sec_index = 0; sec_index < n_sec; sec_index++) {
            if (!(sections[sec_index] = B_PTR(x_malloc(sec_size)))) {

                for (auto ptr_index = 0; ptr_index < sec_index; ptr_index++) {
                    x_free(sections[ptr_index]);
                }

                x_free(sections);
                return_defer(ERROR_NOT_ENOUGH_MEMORY);
            }

            const auto end          = (sec_index + 1) * sec_size;
            const auto copy_size    = (end > n_data) ? n_data - sec_index * sec_size : sec_size;

            x_memcpy(sections[sec_index], data + sec_index * sec_size, copy_size);

            if (copy_size < sec_size) {
                x_memset(sections[sec_index] + copy_size, 0, sec_size - copy_size);
            }
        }

        defer:
        return sections;
    }

    VOID XteaCrypt(uint8_t *const data, const size_t n_data, uint8_t *const m_key, const bool encrypt) {

        _ciphertext *text       = { };
        uint8_t     **sections  = { };
        uint8_t     *buffer     = { };
        uint8_t     *key        = { };

        size_t      n_sect      = { };
        int32_t     offset      = 0;

        m_key ? key = m_key : key = Ctx->config.key;

        x_assert(text = (_ciphertext*) x_malloc(sizeof(_ciphertext)));
        InitCipher(text, key);

        x_assert(sections = XteaDivide(data, n_data, &n_sect));
        x_memset(data, 0, n_data);


        for (auto sec_index = 0; sec_index < n_sect; sec_index++) {
            x_assert(buffer = B_PTR(x_malloc(8)));

            if (encrypt) {
                XteaEncrypt(text, buffer, sections[sec_index]);
            }
            else {
                XteaDecrypt(text, buffer, sections[sec_index]);
            }

            x_memcpy(RVA(uint8_t*, data, offset), C_PTR(buffer), sizeof(uint64_t));
            x_free(buffer);

            offset += sizeof(uint64_t);
        }

        defer:
        if (sections) {
            for (uint64_t sec_index = 0; sec_index < n_sect; sec_index++) {
                if (sections[sec_index]) {
                    x_free(sections[sec_index]);
                }
                else {
                    break;
                }
            }
        }

        if (sections)   { x_free(sections); }
        if (text)       { x_free(text); }
    }
}
