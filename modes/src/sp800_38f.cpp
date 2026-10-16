#include "sp800_38f.hpp"
#include <cstdint>

using namespace std;

namespace lab {
namespace {

using Semiblock = array<Byte, 8>;
constexpr uint64_t kw_semiblock_limit = uint64_t{1} << 54;
constexpr uint64_t kwp_byte_limit = numeric_limits<uint32_t>::max();
constexpr Semiblock kw_iv = {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
constexpr array<Byte, 4> kwp_prefix = {0xa6, 0x59, 0x59, 0xa6};

void check_round_count(size_t n) {
    if (n > numeric_limits<uint64_t>::max() / 6) {
        throw length_error("Key wrap round index exceeds 64 bits.");
    }
}

void check_kw_size(size_t n) {
    if (n >= kw_semiblock_limit) {
        throw length_error("KW key data must contain fewer than 2^54 semiblocks.");
    }
    check_round_count(n);
}

// XOR t into the most significant semiblock in network byte order.
void xor_counter(Block& b, uint64_t t) {
    for (size_t k = 8; k != 0; --k) {
        b[k - 1] ^= static_cast<Byte>(t);
        t >>= 8;
    }
}

// R occupies an existing output buffer; wrapping reserves its first 8 bytes
// for A, whereas unwrapping stores only R in the output buffer.
void wrap_rounds(const AES& aes, Semiblock& a, Bytes& r, size_t offset) {
    const size_t n = (r.size() - offset) / 8;
    for (unsigned j = 0; j < 6; ++j) {
        for (size_t i = 0; i < n; ++i) {
            Block b;
            copy(a.begin(), a.end(), b.begin());
            copy_n(r.begin() + offset + i * 8, 8, b.begin() + 8);
            b = aes.encrypt(b);
            const uint64_t t = static_cast<uint64_t>(n) * j + i + 1;
            xor_counter(b, t);
            copy_n(b.begin(), 8, a.begin());
            copy_n(b.begin() + 8, 8, r.begin() + offset + i * 8);
        }
    }
    copy(a.begin(), a.end(), r.begin());
}

void unwrap_rounds(const AES& aes, Semiblock& a, Bytes& r) {
    const size_t n = r.size() / 8;
    for (unsigned j = 6; j != 0; --j) {
        for (size_t i = n; i != 0; --i) {
            Block b;
            copy(a.begin(), a.end(), b.begin());
            copy_n(r.begin() + (i - 1) * 8, 8, b.begin() + 8);
            const uint64_t t = static_cast<uint64_t>(n) * (j - 1) + i;
            xor_counter(b, t);
            b = aes.decrypt(b);
            copy_n(b.begin(), 8, a.begin());
            copy_n(b.begin() + 8, 8, r.begin() + (i - 1) * 8);
        }
    }
}

Bytes wrap_buffer(const Bytes& key_data, size_t padding) {
    Bytes out;
    if (out.max_size() < 8 || padding > out.max_size() - 8 ||
        key_data.size() > out.max_size() - 8 - padding) {
        throw length_error("Wrapped key is too large.");
    }
    out.resize(key_data.size() + padding + 8, 0);
    copy(key_data.begin(), key_data.end(), out.begin() + 8);
    return out;
}

void check_wrapped_shape(const Bytes& wrapped_key, size_t minimum) {
    if (wrapped_key.size() < minimum || wrapped_key.size() % 8 != 0) {
        throw invalid_argument("Wrapped key has an invalid byte length.");
    }
}

}  // namespace

Bytes kw_wrap(const AES& aes, const Bytes& key_data) {
    if (key_data.size() < 16 || key_data.size() % 8 != 0) {
        throw invalid_argument("KW key data must be at least 16 bytes and a multiple of 8.");
    }
    check_kw_size(key_data.size() / 8);
    Bytes out = wrap_buffer(key_data, 0);
    Semiblock a = kw_iv;
    wrap_rounds(aes, a, out, 8);
    return out;
}

Bytes kw_unwrap(const AES& aes, const Bytes& wrapped_key) {
    check_wrapped_shape(wrapped_key, 24);
    check_kw_size(wrapped_key.size() / 8 - 1);
    Semiblock a;
    copy_n(wrapped_key.begin(), 8, a.begin());
    Bytes out(wrapped_key.begin() + 8, wrapped_key.end());
    unwrap_rounds(aes, a, out);
    unsigned bad = 0;
    for (size_t i = 0; i < a.size(); ++i) bad |= a[i] ^ kw_iv[i];
    if (bad != 0) throw runtime_error("KW integrity check failed.");
    return out;
}

Bytes kwp_wrap(const AES& aes, const Bytes& key_data) {
    if (key_data.empty()) throw invalid_argument("KWP key data must not be empty.");
    if (key_data.size() > kwp_byte_limit) {
        throw length_error("KWP key data exceeds 2^32-1 bytes.");
    }
    const size_t padding = (8 - key_data.size() % 8) % 8;
    // Compute ceil(length/8) without overflowing size_t on a 32-bit host.
    check_round_count(key_data.size() / 8 + (padding != 0));
    Bytes out = wrap_buffer(key_data, padding);
    Semiblock a;
    copy(kwp_prefix.begin(), kwp_prefix.end(), a.begin());
    uint32_t length = static_cast<uint32_t>(key_data.size());
    for (size_t i = 8; i != 4; --i) {
        a[i - 1] = static_cast<Byte>(length);
        length >>= 8;
    }
    if (out.size() == 16) {
        Block b;
        copy(a.begin(), a.end(), b.begin());
        copy_n(out.begin() + 8, 8, b.begin() + 8);
        b = aes.encrypt(b);
        copy(b.begin(), b.end(), out.begin());
    } else {
        wrap_rounds(aes, a, out, 8);
    }
    return out;
}

Bytes kwp_unwrap(const AES& aes, const Bytes& wrapped_key) {
    check_wrapped_shape(wrapped_key, 16);
    const size_t padded_size = wrapped_key.size() - 8;
    if (padded_size > kwp_byte_limit + uint64_t{1}) {
        throw length_error("KWP wrapped key exceeds the maximum padded byte length.");
    }
    check_round_count(padded_size / 8);
    Semiblock a;
    Bytes out;
    if (wrapped_key.size() == 16) {
        const Block b = aes.decrypt(block(wrapped_key));
        copy_n(b.begin(), 8, a.begin());
        out.assign(b.begin() + 8, b.end());
    } else {
        copy_n(wrapped_key.begin(), 8, a.begin());
        out.assign(wrapped_key.begin() + 8, wrapped_key.end());
        unwrap_rounds(aes, a, out);
    }
    unsigned bad = 0;
    for (size_t i = 0; i < kwp_prefix.size(); ++i) bad |= a[i] ^ kwp_prefix[i];
    uint32_t length = 0;
    for (size_t i = 4; i < 8; ++i) length = (length << 8) | a[i];
    bad |= static_cast<unsigned>(length <= padded_size - 8);
    bad |= static_cast<unsigned>(length > padded_size);
    // Inspect the complete last semiblock even when the prefix/MLI is invalid.
    // A valid MLI permits at most seven padding bytes; no secret-derived index
    // or early exit is needed to check them.
    for (size_t i = padded_size - 8; i < padded_size; ++i) {
        const unsigned mask = 0u - static_cast<unsigned>(i >= length);
        bad |= static_cast<unsigned>(out[i]) & mask;
    }
    if (bad != 0) throw runtime_error("KWP integrity check failed.");
    out.resize(static_cast<size_t>(length));
    return out;
}

}  // namespace lab
