#ifndef AES_SP800_38A_HPP
#define AES_SP800_38A_HPP

#include "common.hpp"

using namespace std;

namespace lab {

// API matches Materials/sp800_38a.cpp; AES and a 16-byte IV are caller-supplied.
// Ciphertexts have no IV prefix. ECB/CBC use PKCS#7 when padding=true; NIST raw
// vectors use padding=false. CFB accepts byte-aligned segments of 8..128 bits,
// including the sample's partial final segment. OFB/CTR share one function for
// encryption and decryption. CTR throws if the counter wraps before the end.
// CBC/CFB need unpredictable IVs; OFB IVs and CTR sequences must not be reused
// with the same key. These modes do not authenticate ciphertext.
// Standard: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
Bytes ecb_encrypt(const AES& aes, const Bytes& in, bool padding = true);
Bytes ecb_decrypt(const AES& aes, const Bytes& d, bool padding = true);
Bytes cbc_encrypt(const AES& aes, const Bytes& in, const Bytes& iv, bool padding = true);
Bytes cbc_decrypt(const AES& aes, const Bytes& d, const Bytes& iv, bool padding = true);
Bytes cfb_encrypt(const AES& aes, const Bytes& d, const Bytes& iv, int segment_bits = 128);
Bytes cfb_decrypt(const AES& aes, const Bytes& d, const Bytes& iv, int segment_bits = 128);
Bytes ofb_crypt(const AES& aes, const Bytes& d, const Bytes& iv);
Bytes ctr_crypt(const AES& aes, const Bytes& d, const Bytes& iv);

}  // namespace lab

#endif
