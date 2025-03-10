#include <core/include/cipher.hpp>
namespace Xtea {

    VOID Uint32ToBlock(const uint32 v0, const uint32 v1, uint8 *dst)  {

        dst[0] = v0 >> 24; dst[1] = v0 >> 16; dst[2] = v0 >> 8; dst[3] = v0;
        dst[4] = v1 >> 24; dst[5] = v1 >> 16; dst[6] = v1 >> 8; dst[7] = v1;
    }

    VOID XteaEncrypt(const _ciphertext *const cipher, uint8 *const dst, const uint8 *const src) {

        _u32_block block = {
            block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3],
            block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7],
        };

        for (auto i = 0; i < NROUNDS;) {
            block.v0 += (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ cipher->table[i]; i++;
            block.v1 += (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ cipher->table[i]; i++;
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    VOID XteaDecrypt(const _ciphertext *const cipher, uint8 *const dst, const uint8 *const src) {

        _u32_block block = {
            block.v0 = src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3],
            block.v1 = src[4] << 24 | src[5] << 16 | src[6] << 8 | src[7],
        };

        for (auto i = NROUNDS; i > 0;) {
            i--; block.v1 -= (block.v0 << 4 ^ block.v0 >> 5) + block.v0 ^ cipher->table[i];
            i--; block.v0 -= (block.v1 << 4 ^ block.v1 >> 5) + block.v1 ^ cipher->table[i];
        }

        Uint32ToBlock(block.v0, block.v1, dst);
    }

    PBYTE *XteaDivide (const uint8 *const data, const size_t n_data, size_t *const n_out) {
        HEXANE;

        const auto n_sec    = (n_data + 8) -1 / 8;
        const auto sections = (uint8**) Malloc(n_sec * sizeof(uint8*));

        for (auto index = 0; index < n_sec; index++) {
            if (!(sections[index] = B_PTR(Malloc(sizeof(uint8) * 8)))) {

                for (auto i = 0; i < index; i++) {
                    MemSet(sections[i], 0, sizeof(uint64));
                    Free(sections[i]);
                }

                Free(sections);
                goto defer;
            }

            const auto end          = (index + 1) * 8;
            const auto copy_size    = (end > n_data) ? n_data - index * 8 : 8;

            MemCopy(sections[index], data + index * 8, copy_size);

            if (copy_size < 8) {
                MemSet(sections[index] + copy_size, 0, 8 - copy_size);
            }
        }

        *n_out = n_sec;

        defer:
        return sections;
    }

    VOID InitCipher (_ciphertext *const cipher, const uint8 *const m_key) {

        uint32 key[4] = { };
        uint32 sum    = { };

        auto delta = XTEA_DELTA;
        for (uint32 key_index = 0; key_index < ARRAY_LEN(key); key_index++) {

            auto m_index = key_index << 2;
            key[key_index] = m_key[m_index+0] << 24 | m_key[m_index+1] << 16 | m_key[m_index+2] << 8  | m_key[m_index+3];
        }

        for (uint32 blk_index = 0; blk_index < NROUNDS;) {
            cipher->table[blk_index] = sum + key[sum & 3];
            blk_index++;

            sum += delta;
            cipher->table[blk_index] = sum + key[sum >> 11 & 3];
            blk_index++;
        }
    }

    VOID XteaCrypt(uint8 *const data, const size_t n_data, uint8 *const m_key, const bool encrypt) {
        HEXANE;

        uint8 **sections  = nullptr;
        size_t n_secs       = 0;
        int32_t offset      = 0;

        auto cipher     = (_ciphertext*) Malloc(sizeof(_ciphertext));
        const auto key  = m_key ? m_key : ctx->config.session_key;

        InitCipher(cipher, key);

        sections = XteaDivide(data, n_data, &n_secs);
        MemSet(data, 0, n_data);

        for (auto sec_index = 0; sec_index < n_secs; sec_index++) {
            uint8 buffer[8] = { };

            encrypt
				? XteaEncrypt(cipher, buffer, sections[sec_index])
				: XteaDecrypt(cipher, buffer, sections[sec_index]);

            MemCopy(RVA(uint8*, data, offset), C_PTR(buffer), sizeof(uint64));
            MemSet(buffer, 0, 8);

            offset += sizeof(uint64);
        }

        for (uint64 sec_index = 0; sec_index < n_secs; sec_index++) {
            if (sections[sec_index]) {
                MemSet(sections[sec_index], 0, sizeof(uint64));
                Free(sections[sec_index]);
            } else {
                break;
            }
        }

        MemSet(cipher, 0, sizeof(cipher));

        Free(sections);
        Free(cipher);
    }
}

/*
TODO: experimental
namespace Bcrypt {

    BOOL DeriveDHSharedSecret(const BCRYPT_ALG_HANDLE provider_handle, const BCRYPT_KEY_HANDLE private_key, uint8 *server_public, const uint32 server_pub_size, uint8 *shared_secret, uint32 *shared_secret_size) {

        BCRYPT_KEY_HANDLE pub_handle = nullptr;
        uint32 secret_size = 0;

        if (!NT_SUCCESS(ntstatus = BCryptImportKeyPair(provider_handle, nullptr, BCRYPT_DH_PUBLIC_BLOB, &pub_handle, server_public, server_pub_size, 0)) ||
            !NT_SUCCESS(ntstatus = BCryptSecretAgreement(private_key, pub_handle, &hSecretAgreement, 0)) ||
            !NT_SUCCESS(ntstatus = BCryptDeriveKey(hSecretAgreement, BCRYPT_KDF_RAW_SECRET, nullptr, shared_secret, AES_KEY_SIZE, &secret_size, 0))) {
            return false;
        }

        *shared_secret_size = secret_size;
        return NT_SUCCESS(BCryptDestroyKey(pub_handle));
    }

    BOOL DeriveSessionKey(BCRYPT_ALG_HANDLE provider_handle, uint8 *shared_secret, const uint8 *nonce, const uint32 counter, uint8 *session_key) {

        BCRYPT_HASH_HANDLE hash_handle = nullptr;
        uint8 combined[NONCE_SIZE + sizeof(counter)];

        MemCopy(combined, nonce, NONCE_SIZE);
        MemCopy(combined + NONCE_SIZE, &counter, sizeof(counter));

        if (BCryptCreateHash(provider_handle, &hash_handle, nullptr, 0, shared_secret, AES_KEY_SIZE, 0) != 0) {
            return false;
        }
    }

    BOOL FirstKey(uint8 *server_public, const uint32 server_public_size) {

        BCRYPT_ALG_HANDLE provider_handle   = nullptr;
        BCRYPT_KEY_HANDLE private_key       = nullptr;

        bool success = true;

        uint8 session_key[AES_KEY_SIZE]   = { };
        uint8 shared_secret[AES_KEY_SIZE] = { };

        const auto nonce = (uint8*) Malloc(NONCE_SIZE);
        uint32 counter = 0;

        if (!NT_SUCCESS(ntstatus = BCryptOpenAlgorithmProvider(&provider_handle, BCRYPT_DH_ALGORITHM, nullptr, 0)) ||
            !NT_SUCCESS(ntstatus = BCryptGenerateKeyPair(provider_handle, &private_key, DH_KEY_SIZE, 0)) ||
            !NT_SUCCESS(ntstatus = BCryptFinalizeKeyPair(private_key, 0))) {
            success = false;
            goto defer;
        }

        uint32 shared_secret_size = AES_KEY_SIZE;
        if (!DeriveDHSharedSecret(provider_handle, private_key, server_public, server_public_size, shared_secret, &shared_secret_size)) {
            success = false;
            goto defer;
        }

        DeriveSessionKey(provider_handle, shared_secret, nonce, counter, session_key);

        // Cleanup
        if (!NT_SUCCESS(ntstatus = BCryptDestroyKey(private_key)) ||
            !NT_SUCCESS(ntstatus = BCryptCloseAlgorithmProvider(provider_handle, 0))) {
            success = false;
        }

    defer:
        Free(nonce);
        return success;
    }
}
*/

namespace Hash {
    ULONG LdrHashEntry(UNICODE_STRING uni_name, BOOL xor_hash) {
        HEXANE;

        ULONG hash = 0;

        if (!NT_SUCCESS(ntstatus = ctx->win32.RtlHashUnicodeString(&uni_name, TRUE, 0, &hash))) {
            return 0;
        }
        if (xor_hash) {
            hash &= (32 - 1);
        }

        return hash;
    }

    UINT32 HashStringA(char const *string, size_t length) {

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
