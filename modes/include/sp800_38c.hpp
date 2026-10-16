#ifndef AES_SP800_38C_HPP
#define AES_SP800_38C_HPP

#include "common.hpp"

using namespace std;

namespace lab {

// CCM uses a caller-supplied AES key schedule and nonce, like the 38A API.
// Result/input format is ciphertext || encrypted tag, without a nonce prefix.
// nonce: 7..13 bytes; tag_length: 4, 6, 8, 10, 12, 14 or 16 bytes.
// AAD is authenticated but not encrypted. Decryption returns bytes only after
// successful verification; an invalid tag throws runtime_error.
// Empty payload/AAD are valid. Payload size must be < 2^(8*(15-nonce.size())).
// Never reuse a nonce under the same key; keep the tag length fixed per key.
// Standard: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
Bytes ccm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
                  const Bytes& associated_data = {}, int tag_length = 16);
Bytes ccm_decrypt(const AES& aes, const Bytes& ciphertext_and_tag, const Bytes& nonce,
                  const Bytes& associated_data = {}, int tag_length = 16);

}  // namespace lab

#endif
