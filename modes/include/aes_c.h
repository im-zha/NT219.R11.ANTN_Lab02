#ifndef AES_MODES_C_H
#define AES_MODES_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#define AES_MODES_NOEXCEPT noexcept
extern "C" {
#else
#define AES_MODES_NOEXCEPT
#endif

/* C ABI for foreign-language callers. All lengths are bytes, except CFB bits.
 * Existing C++ APIs remain unchanged. No exception crosses this boundary.
 * Pointer/length inputs may be NULL only when the corresponding length is zero.
 * Handles must come from this library; do not use them after destruction.
 * Every successful result is owned by the caller and must be destroyed with
 * aes_modes_buffer_destroy (including a zero-length result). A failed call
 * leaves *out NULL. Release an earlier result before reusing its output slot.
 * Buffers remain valid independently of the key handle. Never free their data
 * pointer directly. aes_modes_last_error is thread-local and is replaced by the
 * next status-returning call on the same thread; destroy/accessor calls do not
 * replace it. No function generates or prefixes an IV/nonce/tweak.
 */
typedef struct aes_modes_key aes_modes_key;
typedef struct aes_modes_buffer aes_modes_buffer;

enum aes_modes_status {
    AES_MODES_OK = 0,
    AES_MODES_INVALID_ARGUMENT = 1,
    AES_MODES_AUTH_FAILED = 2,
    AES_MODES_LENGTH_ERROR = 3,
    AES_MODES_COUNTER_OVERFLOW = 4,
    AES_MODES_OUT_OF_MEMORY = 5,
    AES_MODES_INTERNAL_ERROR = 6
};

const char* aes_modes_last_error(void) AES_MODES_NOEXCEPT;
int aes_modes_key_create(const uint8_t* key, size_t key_size,
                         aes_modes_key** out) AES_MODES_NOEXCEPT;
void aes_modes_key_destroy(aes_modes_key* key) AES_MODES_NOEXCEPT;
const uint8_t* aes_modes_buffer_data(const aes_modes_buffer* buffer) AES_MODES_NOEXCEPT;
size_t aes_modes_buffer_size(const aes_modes_buffer* buffer) AES_MODES_NOEXCEPT;
void aes_modes_buffer_destroy(aes_modes_buffer* buffer) AES_MODES_NOEXCEPT;

/* Raw AES blocks: exactly 16 input/output bytes; keys contain 16, 24 or 32 bytes. */
int aes_modes_encrypt_block(const aes_modes_key* key, const uint8_t* input,
                            size_t size, aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_decrypt_block(const aes_modes_key* key, const uint8_t* input,
                            size_t size, aes_modes_buffer** out) AES_MODES_NOEXCEPT;

/* 38A: padding is 0 or 1 (PKCS#7). IV/counter is exactly 16 bytes.
 * CFB segment_bits is byte-aligned in 8..128. OFB/CTR are symmetric.
 * CBC/CFB IVs must be unpredictable; OFB IVs and CTR sequences must not repeat
 * under a key. These modes provide no authentication.
 */
int aes_modes_ecb_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          int padding, aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_ecb_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          int padding, aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_cbc_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* iv, size_t iv_size, int padding,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_cbc_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* iv, size_t iv_size, int padding,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_cfb_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* iv, size_t iv_size, int segment_bits,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_cfb_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* iv, size_t iv_size, int segment_bits,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_ofb_crypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                        const uint8_t* iv, size_t iv_size,
                        aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_ctr_crypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                        const uint8_t* counter, size_t counter_size,
                        aes_modes_buffer** out) AES_MODES_NOEXCEPT;

/* CMAC/GMAC return full 16-byte tags. Verify writes 0/1 to *valid and returns OK
 * for a mismatch; malformed non-tag parameters still produce an error status.
 */
int aes_modes_cmac(const aes_modes_key* key, const uint8_t* input, size_t size,
                   aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_cmac_verify(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* tag, size_t tag_size,
                          int* valid) AES_MODES_NOEXCEPT;
int aes_modes_gmac(const aes_modes_key* key, const uint8_t* input, size_t size,
                   const uint8_t* nonce, size_t nonce_size,
                   aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_gmac_verify(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* tag, size_t tag_size,
                          int* valid) AES_MODES_NOEXCEPT;

/* GCM/CCM return/accept ciphertext || tag and release plaintext only after
 * authentication. GCM: nonce 12 bytes, tag 16 bytes. CCM: nonce 7..13 bytes,
 * tag_size in {4,6,8,10,12,14,16}. Empty payload/AAD are supported.
 * A nonce must never repeat under the same key.
 */
int aes_modes_gcm_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* aad, size_t aad_size,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_gcm_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* aad, size_t aad_size,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_ccm_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* aad, size_t aad_size, int tag_size,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_ccm_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* aad, size_t aad_size, int tag_size,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;

/* KW/KWP wrap key material, not arbitrary padded text. KW: >=16 and multiple8;
 * KWP: nonempty. Unwrap checks integrity before returning key material.
 */
int aes_modes_kw_wrap(const aes_modes_key* key, const uint8_t* input, size_t size,
                      aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_kw_unwrap(const aes_modes_key* key, const uint8_t* input, size_t size,
                        aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_kwp_wrap(const aes_modes_key* key, const uint8_t* input, size_t size,
                       aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_kwp_unwrap(const aes_modes_key* key, const uint8_t* input, size_t size,
                         aes_modes_buffer** out) AES_MODES_NOEXCEPT;

/* XTS takes a raw concatenated 32/64-byte key with distinct halves, a 16-byte
 * tweak, and a 16..16*2^20-byte data unit. No authentication or extra padding.
 */
int aes_modes_xts_encrypt(const uint8_t* key, size_t key_size,
                          const uint8_t* input, size_t size,
                          const uint8_t* tweak, size_t tweak_size,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_xts_decrypt(const uint8_t* key, size_t key_size,
                          const uint8_t* input, size_t size,
                          const uint8_t* tweak, size_t tweak_size,
                          aes_modes_buffer** out) AES_MODES_NOEXCEPT;

/* RFC8452 takes a raw 16/32-byte key, a 12-byte nonce, and a full trailing
 * 16-byte tag. Empty payload/AAD are supported. Nonces should remain unique.
 */
int aes_modes_gcm_siv_encrypt(const uint8_t* key, size_t key_size,
                              const uint8_t* input, size_t size,
                              const uint8_t* nonce, size_t nonce_size,
                              const uint8_t* aad, size_t aad_size,
                              aes_modes_buffer** out) AES_MODES_NOEXCEPT;
int aes_modes_gcm_siv_decrypt(const uint8_t* key, size_t key_size,
                              const uint8_t* input, size_t size,
                              const uint8_t* nonce, size_t nonce_size,
                              const uint8_t* aad, size_t aad_size,
                              aes_modes_buffer** out) AES_MODES_NOEXCEPT;

#ifdef __cplusplus
}
#endif
#undef AES_MODES_NOEXCEPT
#endif
