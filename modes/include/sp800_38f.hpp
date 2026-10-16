#ifndef AES_MODES_SP800_38F_HPP
#define AES_MODES_SP800_38F_HPP

#include "common.hpp"

namespace lab {

// Deterministic AES key wrapping: no nonce or caller IV; AES supplies the KEK.
// SP800-38F sections 6.2/6.3, using AES encryption as the designated cipher:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
// https://www.rfc-editor.org/rfc/rfc3394 (KW)
// https://www.rfc-editor.org/rfc/rfc5649 (KWP)
// Lengths are bytes. Bad input shape throws invalid_argument; size limits throw
// length_error. Unwrap returns key data only after all integrity checks pass,
// otherwise throwing runtime_error. All AES key sizes are supported.

// KW uses the fixed A6A6A6A6A6A6A6A6 IV. Input is at least 16 bytes, a multiple
// of 8, and fewer than 2^54 semiblocks; the output is 8 bytes longer.
Bytes kw_wrap(const AES& aes, const Bytes& key_data);
// Wrapped input is at least 24 bytes and a multiple of 8.
Bytes kw_unwrap(const AES& aes, const Bytes& wrapped_key);

// KWP uses A65959A6 || big-endian byte length as its IV, with zero padding.
// Input contains 1..2^32-1 bytes; output is 8 + 8*ceil(input_length/8) bytes.
Bytes kwp_wrap(const AES& aes, const Bytes& key_data);
// Wrapped input is at least 16 bytes and a multiple of 8. Validates the IV,
// embedded byte length and every padding byte before removing padding.
Bytes kwp_unwrap(const AES& aes, const Bytes& wrapped_key);

}  // namespace lab

#endif
