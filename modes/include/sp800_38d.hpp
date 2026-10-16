#ifndef AES_SP800_38D_HPP
#define AES_SP800_38D_HPP

#include "common.hpp"

using namespace std;

namespace lab {

// AES-GCM with a caller-supplied 12-byte nonce and full 16-byte tag.
// Encrypt returns ciphertext || tag; decrypt accepts that format, without a
// nonce prefix. Empty payload/AAD are valid. Never reuse a nonce with one key.
// Payload: at most 2^36 - 32 bytes; AAD: at most 2^61 - 1 bytes.
// Invalid nonce: invalid_argument; size limit: length_error; failed/missing tag:
// runtime_error. Decryption authenticates before allocating/recovering plaintext.
// Standard: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
Bytes gcm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
                  const Bytes& associated_data = {});
Bytes gcm_decrypt(const AES& aes, const Bytes& ciphertext_and_tag, const Bytes& nonce,
                  const Bytes& associated_data = {});

// GMAC authenticates data as GCM AAD with an empty payload; returns a 16-byte
// tag only. The same nonce requirements and AAD size limit above apply.
// Verification returns false for an incorrect tag value or length; invalid
// nonce/oversized authenticated_data still throw invalid_argument/length_error.
Bytes gmac(const AES& aes, const Bytes& authenticated_data, const Bytes& nonce);
bool gmac_verify(const AES& aes, const Bytes& authenticated_data, const Bytes& tag,
                 const Bytes& nonce);

}  // namespace lab

#endif
