#include <core/include/cipher.hpp>
#include <core/monolith.hpp>

namespace Xtea {
    VOID Uint32ToBlock(const UINT32 v0, const UINT32 v1, UINT8 *dst)  {
        dst[0] = v0 >> 24; dst[1] = v0 >> 16; dst[2] = v0 >> 8; dst[3] = v0;
        dst[4] = v1 >> 24; dst[5] = v1 >> 16; dst[6] = v1 >> 8; dst[7] = v1;
    }

    VOID XteaEncrypt(const CIPHERTEXT *const cipher, UINT8 *const dst, const UINT8 *const src) {
        U32_BLOCK block = {
            block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3],
            block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7],
        };

        for (auto i = 0; i < NROUNDS;) {
            block.v0 += (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ cipher->table[i]; i++;
            block.v1 += (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ cipher->table[i]; i++;
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    VOID XteaDecrypt(const CIPHERTEXT *const cipher, UINT8 *const dst, const UINT8 *const src) {
        U32_BLOCK block = {
            block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3],
            block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7],
        };

        for (auto i = NROUNDS; i > 0;) {
            i--; block.v1 -= (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ cipher->table[i];
            i--; block.v0 -= (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ cipher->table[i];
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    PBYTE *XteaDivide (const UINT8 *const data, const SIZE_T nData, SIZE_T* const nOut) {
        const auto nSections = (nData + 8) -1 / 8;
        const auto sections = (UINT8**) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, nSections * sizeof(UINT8*));

        for (auto index = 0; index < nSections; index++) {
            if (!(sections[index] = (PBYTE) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(uint8) * 8))) {

                for (auto i = 0; i < index; i++) {
                    MemSet(sections[i], 0, sizeof(uint64));
                    Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, sections[i]);
                }
                Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, sections);
                goto defer;
            }

            const auto end          = (index + 1) * 8;
            const auto copySize    = (end > nData) ? nData - index * 8 : 8;

            MemCopy(sections[index], data + index * 8, copySize);

            if (copySize < 8) {
                MemSet(sections[index] + copySize, 0, 8 - copySize);
            }
        }

        *nOut = nSections;
defer:
        return sections;
    }

    VOID InitCipher (CIPHERTEXT *const cipher, const UINT8 *const mKey) {
        UINT32 sum = 0;
        UINT32 key[4] = { };

        auto delta = XTEA_DELTA;
        for (uint32 idx = 0; idx < ARRAY_LEN(key); idx++) {

            auto mIdx = idx << 2;
            key[idx] = mKey[mIdx+0] << 24 | mKey[mIdx+1] << 16 | mKey[mIdx+2] << 8  | mKey[mIdx+3];
        }

        for (uint32 idx = 0; idx < NROUNDS;) {
            cipher->table[idx] = sum + key[sum & 3];
            idx++;

            sum += delta;
            cipher->table[idx] = sum + key[sum >> 11 & 3];
            idx++;
        }
    }

    VOID XteaCrypt(UINT8 *const data, const SIZE_T nData, UINT8 *const mKey, const BOOL encrypt) {
        UINT8 **sections  	= nullptr;
        SIZE_T nSecs		= 0;
        INT32 offset      	= 0;

        auto cipher     = (CIPHERTEXT*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, sizeof(CIPHERTEXT));
        const auto key  = mKey ? mKey : ctx->config.session_key;

        InitCipher(cipher, key);

        sections = XteaDivide(data, nData, &nSecs);
        MemSet(data, 0, nData);

        for (auto idx = 0; idx < nSecs; idx++) {
            UINT8 buffer[8] = { };

            encrypt
				? XteaEncrypt(cipher, buffer, sections[idx])
				: XteaDecrypt(cipher, buffer, sections[idx]);

            MemCopy(RVA(UINT8*, data, offset), (LPVOID)buffer, sizeof(UINT64));
            MemSet(buffer, 0, 8);

            offset += sizeof(UINT64);
        }

        for (UINT64 idx = 0; idx < nSecs; idx++) {
            if (sections[idx]) {
                MemSet(sections[idx], 0, sizeof(UINT64));
                Free(sections[idx]);
            } else {
                break;
            }
        }

        MemSet(cipher, 0, sizeof(cipher));

        Free(sections);
        Free(cipher);
    }
}

namespace Hash {
    ULONG LdrHashEntry(UNICODE_STRING uniName, BOOL xorHash) {
        ULONG hash = 0;

        ctx->win32.RtlHashUnicodeString(&uni_name, TRUE, 0, &hash); 
		if (!NT_SUCCESS(Ctx->Teb->LastErrorValue)) {
            return 0;
        }
        if (xorHash) {
            hash &= (32 - 1);
        }
        return hash;
    }

    UINT32 HashStringA(CHAR const *string, SIZE_T length) {
        auto hash = FNV_OFFSET;

		if (!length) {
			return 0;
		}
        if (string) {
            for (auto i = 0; i < length; i++) {
                hash ^= string[i];
                hash *= FNV_PRIME;
            }
        }
        return hash;
    }

    UINT32 HashStringW(wchar_t const *string, size_t length) {
        auto hash = FNV_OFFSET;
		if (!length) {
			return 0;
		}
        if (string) {
            for (auto i = 0; i < length; i++) {
                hash ^= string[i];
                hash *= FNV_PRIME;
            }
        }
        return hash;
    }
}
