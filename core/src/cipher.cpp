#include <core/include/cipher.hpp>
namespace Xtea {

    _u32_block BlockToUint32 (const byte *src) {

        _u32_block block = { };

        block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3];
        block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7];

        return block;
    }

    VOID Uint32ToBlock (uint32_t v0, uint32_t v1, byte *dst)  {

        dst[0] = v0 >> 24;
        dst[1] = v0 >> 16;
        dst[2] = v0 >> 8;
        dst[3] = v0;
        dst[4] = v1 >> 24;
        dst[5] = v1 >> 16;
        dst[6] = v1 >> 8;
        dst[7] = v1;
    }

    VOID InitCipher (_ciphertext *c, const uint8_t *m_key) {

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

    VOID XteaEncrypt(_ciphertext *c, byte *dst, byte *src) {

        _u32_block block = BlockToUint32(src);
        for (auto i = 0; i < NROUNDS;) {
            block.v0 += (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ c->table[i];
            i++;

            block.v1 += (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ c->table[i];
            i++;
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    VOID XteaDecrypt(_ciphertext *c, uint8_t *dst, uint8_t *src) {

        _u32_block block = BlockToUint32(src);
        for (auto i = NROUNDS; i > 0;) {
            i--;
            block.v1 -= (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ c->table[i];

            i--;
            block.v0 -= (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ c->table[i];
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    PBYTE *XteaDivide (uint8_t *data, size_t n_data, size_t *n_out) {
        HEXANE

        uint8_t **sections = { };
        size_t sectionSize  = 8;
        size_t n = (n_data + sectionSize - 1) / sectionSize;
        *n_out = n;

        if (!(sections = S_CAST(PBYTE*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, n * sizeof(PBYTE))))) {
            return nullptr;
        }

        for (size_t i = 0; i < n; i++) {
            if (!(sections[i] = S_CAST(PBYTE, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sectionSize)))) {

                for (size_t j = 0; j < i; j++) {
                    Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections[j]);
                }

                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections);
                return_defer(ERROR_NOT_ENOUGH_MEMORY);
            }

            size_t end = (i + 1) * sectionSize;
            size_t copySize = (end > n_data) ? n_data - i * sectionSize : sectionSize;

            x_memcpy(sections[i], data + i * sectionSize, copySize);

            if (copySize < sectionSize) {
                x_memset(sections[i] + copySize, 0, sectionSize - copySize);
            }
        }

        defer:
        return sections;
    }

    VOID XteaCrypt(uint8_t *data, size_t n_data, const uint8_t *key, const bool encrypt) {
        HEXANE

        _ciphertext *text = { };
        size_t n_sect    = { };
        uint64_t offset  = 0;

        byte *buffer    = { };
        byte **sections = { };

        if (!key) {
            key = Ctx->Config.Key;
        }

        if (!(text = S_CAST(_ciphertext*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(_ciphertext))))) {
            return;
        }

        InitCipher(text, key);
        if (!(sections = XteaDivide(data, n_data, &n_sect))) {
            return;
        }

        x_memset(data, 0, n_data);

        for (uint32_t i = 0; i < n_sect; i++) {
            if (!(buffer = B_PTR(Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, 8)))) {
                return;
            }
            if (encrypt) {
                XteaEncrypt(text, buffer, sections[i]);
            } else {
                XteaDecrypt(text, buffer, sections[i]);
            }

            Memory::PatchMemory(data, buffer, offset, 0, sizeof(uint64_t));

            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, buffer);
            offset += sizeof(uint64_t);
        }

        for (uint64_t i = 0; i < n_sect; i++) {
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections[i]);
        }

        Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections);
        Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, text);
    }
}
