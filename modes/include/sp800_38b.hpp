#ifndef AES_SP800_38B_HPP
#define AES_SP800_38B_HPP

#include "common.hpp"

using namespace std;

namespace lab {

// AES-CMAC authenticates binary messages; it does not encrypt them.
// Uses the supplied AES-128/192/256 schedule with a key reserved for CMAC.
// Message length is in bytes and may be zero. No caller nonce, IV or tweak is
// used. Returns the full 16-byte tag; truncation is not supported.
// Standard: https://doi.org/10.6028/NIST.SP.800-38B (Sections 6.1-6.3).
Bytes cmac(const AES& aes, const Bytes& message);

// Returns false for a wrong tag length or value, rather than throwing an
// authentication error. For a 16-byte tag, compares all bytes without a
// content-dependent early return. No message-length restriction is imposed.
bool cmac_verify(const AES& aes, const Bytes& message, const Bytes& tag);

}  // namespace lab

#endif
