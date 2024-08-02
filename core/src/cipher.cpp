#include "core/corelib.hpp"
namespace Xtea {

    U32_BLOCK BlockToUint32 (const byte *src) {

        U32_BLOCK block = { };

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

    VOID InitCipher (CipherTxt *c, const byte *m_key) {

        uint32_t key[4] = { };
        uint32_t sum    = { };

        auto delta = XTEA_DELTA;

        for (uint32_t i = 0; i < ARRAY_LEN(key); i++) {
            uint32_t j = i << 2;

            key[i] =
                SCAST(uint32_t, m_key[j+0]) << 24 |
                SCAST(uint32_t, m_key[j+1]) << 16 |
                SCAST(uint32_t, m_key[j+2]) << 8  |
                SCAST(uint32_t, m_key[j+3]);
        }

        for (uint32_t i = 0; i < NROUNDS;) {
            c->table[i] = sum + key[sum & 3];
            i++;

            sum += delta;
            c->table[i] = sum + key[sum >> 11 & 3];
            i++;
        }
    }

    VOID XteaEncrypt(CipherTxt *c, byte *dst, byte *src) {

        U32_BLOCK block = BlockToUint32(src);

        for (auto i = 0; i < NROUNDS;) {
            block.v0 += (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ c->table[i];
            i++;

            block.v1 += (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ c->table[i];
            i++;
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    VOID XteaDecrypt(CipherTxt *c, byte *dst, byte *src) {

        U32_BLOCK block = BlockToUint32(src);

        for (auto i = NROUNDS; i > 0;) {
            i--;
            block.v1 -= (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ c->table[i];

            i--;
            block.v0 -= (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ c->table[i];
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    PBYTE *XteaDivide (byte *data, size_t cbData, size_t *cbOut) {
        HEXANE

        byte **sections = { };
        size_t sectionSize  = 8;
        size_t n = (cbData + sectionSize - 1) / sectionSize;

        *cbOut = n;
        if (!(sections = SCAST(PBYTE*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, n * sizeof(PBYTE))))) {
            return nullptr;
        }

        for (size_t i = 0; i < n; i++) {
            if (!(sections[i] = SCAST(PBYTE, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sectionSize)))) {

                for (size_t j = 0; j < i; j++) {
                    Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections[j]);
                }

                Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections);
                return_defer(ERROR_NOT_ENOUGH_MEMORY);
            }

            size_t end = (i + 1) * sectionSize;
            size_t copySize = (end > cbData) ? cbData - i * sectionSize : sectionSize;

            x_memcpy(sections[i], data + i * sectionSize, copySize);

            if (copySize < sectionSize) {
                x_memset(sections[i] + copySize, 0, sectionSize - copySize);
            }
        }

        defer:
        return sections;
    }

    VOID XteaCrypt(PBYTE data, SIZE_T cbData, PBYTE key, BOOL encrypt) {
        HEXANE

        CipherTxt *text     = { };
        size_t nSections    = { };
        uint64_t offset     = 0;

        byte *buffer    = { };
        byte **sections = { };

        if (!key) {
            key = Ctx->Config.Key;
        }

        if (!(text = SCAST(CipherTxt*, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(CipherTxt))))) {
            return;
        }

        InitCipher(text, key);
        if (!(sections = XteaDivide(data, cbData, &nSections))) {
            return;
        }

        x_memset(data, 0, cbData);

        for (uint32_t i = 0; i < nSections; i++) {
            if (!(buffer = SCAST(PBYTE, Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, 8)))) {
                return;
            }

            if (encrypt) {
                XteaEncrypt(text, buffer, sections[i]);
            } else {
                XteaDecrypt(text, buffer, sections[i]);
            }

            MmPatchData(j, data, (j + offset), buffer, (j), sizeof(uint64_t));
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, buffer);

            offset += sizeof(uint64_t);
        }

        for (uint64_t i = 0; i < nSections; i++) {
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections[i]);
        }

        Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections);
        Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, text);
    }
}