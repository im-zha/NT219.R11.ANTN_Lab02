#ifndef AES_SP800_38E_HPP
#define AES_SP800_38E_HPP

#include "common.hpp"

using namespace std;

namespace lab {

// XTS-AES storage confidentiality only: no authentication or integrity protection.
// key = data key || tweak key: 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS),
// with distinct halves. tweak is exactly 16 caller-supplied bytes, used verbatim;
// it is not generated, prefixed, or interpreted as a numeric data-unit identifier.
// Each data unit contains 16..16*2^20 bytes; ciphertext stealing preserves length
// without padding. Use a fixed data-unit length per key and distinct tweaks for
// distinct storage locations; decryption needs the same key and tweak.
// Bad key/tweak lengths, equal key halves, or short units: invalid_argument.
// Units exceeding the SP 800-38E limit: length_error. No tampering is detected.
// Standards: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf
// https://standards.ieee.org/ieee/1619/4205/
Bytes xts_encrypt(const Bytes& key, const Bytes& plaintext, const Bytes& tweak);
Bytes xts_decrypt(const Bytes& key, const Bytes& ciphertext, const Bytes& tweak);

}  // namespace lab

#endif
