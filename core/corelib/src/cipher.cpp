#include <core/corelib/include/cipher.hpp>
namespace Xtea {

    U32_BLOCK BlockToUint32 (const byte *src) {

        U32_BLOCK block = { };

        block.v0 = (src[0]) << 24 | (src[1]) << 16 | (src[2]) << 8 | src[3];
        block.v1 = (src[4]) << 24 | (src[5]) << 16 | (src[6]) << 8 | src[7];

        return block;
    }

    VOID Uint32ToBlock (uint32_t v0, uint32_t v1, byte *dst)  {

        dst[0] = (v0 >> 24);
        dst[1] = (v0 >> 16);
        dst[2] = (v0 >> 8);
        dst[3] = (v0);
        dst[4] = (v1 >> 24);
        dst[5] = (v1 >> 16);
        dst[6] = (v1 >> 8);
        dst[7] = (v1);
    }

    VOID InitCipher (CipherTxt *c, const byte *m_key) {

        uint32_t key[4] = { };
        uint32_t sum    = { };

        auto delta = XTEA_DELTA;

        for (uint32_t i = 0; i < ARRAY_LEN(key); i++) {
            uint32_t j = i << 2;

            key[i] =
                CSTATIC(uint32_t, m_key[j+0]) << 24 |
                CSTATIC(uint32_t, m_key[j+1]) << 16 |
                CSTATIC(uint32_t, m_key[j+2]) << 8  |
                CSTATIC(uint32_t, m_key[j+3]);
        }

        for (uint32_t i = 0; i < NROUNDS;) {
            c->table[i] = sum + key[sum & 3];
            i++;

            sum += delta;
            c->table[i] = sum + key[(sum >> 11) & 3];
            i++;
        }
    }

    VOID XteaEncrypt(CipherTxt *c, byte *dst, byte *src) {

        U32_BLOCK block = BlockToUint32(src);

        for (auto i = 0; i < NROUNDS;) {
            block.v0 += (((block.v1 << 4) ^ (block.v1 >> 5)) + block.v1) ^ (c->table[i]);
            i++;

            block.v1 += (((block.v0 << 4) ^ (block.v0 >> 5)) + block.v0) ^ (c->table[i]);
            i++;
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    VOID XteaDecrypt(CipherTxt *c, byte *dst, byte *src) {

        U32_BLOCK block = BlockToUint32(src);

        for (auto i = NROUNDS; i > 0;) {
            i--;
            block.v1 -= (((block.v0 << 4) ^ (block.v0 >> 5)) + block.v0) ^ (c->table[i]);

            i--;
            block.v0 -= (((block.v1 << 4) ^ (block.v1 >> 5)) + block.v1) ^ (c->table[i]);
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    PBYTE *XteaDivide (byte *data, size_t cbData, size_t *cbOut) {
        HEXANE

        size_t sectionSize  = 8;
        size_t n = (cbData + sectionSize - 1) / sectionSize;

        byte **sections = { };
        *cbOut = n;

        if (!(sections = reinterpret_cast<PBYTE*>(Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, n * sizeof(PBYTE))))) {
            return nullptr;
        }

        for (size_t i = 0; i < n; i++) {
            if (!(sections[i] = reinterpret_cast<PBYTE>(Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sectionSize)))) {

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
        HEXANE;

        CipherTxt *cx       = { };
        uint64_t ofs        = 0;
        size_t nSections    = { };

        byte *buffer    = { };
        byte **sections = { };

        if (!key) {
            key = Ctx->Config.Key;
        }

        if (!(cx = reinterpret_cast<CipherTxt*>(Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, sizeof(CipherTxt))))) {
            return;
        }

        InitCipher(cx, key);
        if (!(sections = XteaDivide(data, cbData, &nSections))) {
            return;
        }

        x_memset(data, 0, cbData);

        for (uint32_t i = 0; i < nSections; i++) {
            buffer = reinterpret_cast<PBYTE*>(Ctx->Nt.RtlAllocateHeap(Ctx->Heap, 0, 8));

            if (encrypt) {
                XteaEncrypt(cx, buffer, sections[i]);
            } else {
                XteaDecrypt(cx, buffer, sections[i]);
            }

            MmPatchData(j, data, (j + ofs), buffer, (j), sizeof(uint64_t));
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, buffer);

            ofs += sizeof(uint64_t);
        }

        for (uint64_t i = 0; i < nSections; i++) {
            Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections[i]);
        }

        Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, sections);
        Ctx->Nt.RtlFreeHeap(Ctx->Heap, 0, cx);
    }
}