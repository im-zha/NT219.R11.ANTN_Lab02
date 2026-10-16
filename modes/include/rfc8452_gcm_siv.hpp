#ifndef AES_RFC8452_GCM_SIV_HPP
#define AES_RFC8452_GCM_SIV_HPP

#include "common.hpp"

using namespace std;

namespace lab {

// AES-GCM-SIV: key is exactly 16 or 32 bytes; caller supplies a 12-byte nonce.
// Output/input is ciphertext || a fixed 16-byte tag, with no nonce prefix.
// Plaintext and associated_data may be empty and are each at most 2^36 bytes.
// Nonces should be unique per key; reuse reveals equality of messages, even
// though this mode resists the catastrophic nonce-reuse failures of GCM.
// Decryption releases plaintext only after checking the entire tag.
// Invalid key/nonce or input shorter than the tag: invalid_argument.
// Size limits: length_error; a present but invalid tag: runtime_error.
// Specification: https://www.rfc-editor.org/rfc/rfc8452
Bytes gcm_siv_encrypt(const Bytes& key, const Bytes& plaintext, const Bytes& nonce,
                      const Bytes& associated_data = {});
Bytes gcm_siv_decrypt(const Bytes& key, const Bytes& ciphertext_and_tag, const Bytes& nonce,
                      const Bytes& associated_data = {});

}  // namespace lab

#endif
