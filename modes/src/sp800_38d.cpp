#include "sp800_38d.hpp"

using namespace std;

namespace lab {
namespace {

void validate_gcm_nonce(const Bytes& nonce) {
    if (nonce.size() != 12) {
        throw invalid_argument("AES-GCM nonce must contain exactly 12 bytes.");
    }
}

void validate_gcm_lengths(size_t payload_length, size_t aad_length) {
    if (payload_length > (uint64_t{1} << 36) - 32) {
        throw length_error("AES-GCM payload must contain at most 2^36 - 32 bytes.");
    }
    if (aad_length > numeric_limits<uint64_t>::max() / 8) {
        throw length_error("AES-GCM associated data bit length must fit in 64 bits.");
    }
}

uint64_t load_gcm_word(const Byte* input) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | input[i];
    return value;
}

void store_gcm_word(Byte* output, uint64_t value) {
    for (size_t i = 8; i > 0; --i) {
        output[i - 1] = static_cast<Byte>(value);
        value >>= 8;
    }
}

// SP 800-38D Algorithms 1-2: consume bits most-significant first, shift the
// multiplier right, and reduce by R = e1 || 0^120. No data-dependent tables.
class Ghash {
public:
    explicit Ghash(const Block& hash_subkey)
        : hash_high_(load_gcm_word(hash_subkey.data())),
          hash_low_(load_gcm_word(hash_subkey.data() + 8)) {}

    // Each call is a separate padded field: AAD and ciphertext must not share
    // a partial block. Empty/aligned fields do not add a zero padding block.
    void append_padded(const Byte* data, size_t length) {
        while (length >= 16) {
            absorb(data);
            data += 16;
            length -= 16;
        }
        if (length != 0) {
            Block tail{};
            copy_n(data, length, tail.begin());
            absorb(tail.data());
        }
    }

    Block finish(size_t aad_length, size_t ciphertext_length) {
        Block lengths{};
        store_gcm_word(lengths.data(), static_cast<uint64_t>(aad_length) * 8);
        store_gcm_word(lengths.data() + 8, static_cast<uint64_t>(ciphertext_length) * 8);
        absorb(lengths.data());
        Block result{};
        store_gcm_word(result.data(), high_);
        store_gcm_word(result.data() + 8, low_);
        return result;
    }

private:
    const uint64_t hash_high_;
    const uint64_t hash_low_;
    uint64_t high_ = 0;
    uint64_t low_ = 0;

    void absorb(const Byte* data) {
        const array<uint64_t, 2> words{{high_ ^ load_gcm_word(data),
                                       low_ ^ load_gcm_word(data + 8)}};
        uint64_t product_high = 0;
        uint64_t product_low = 0;
        uint64_t factor_high = hash_high_;
        uint64_t factor_low = hash_low_;
        for (uint64_t word : words) {
            for (unsigned bit = 0; bit < 64; ++bit) {
                const uint64_t mask = uint64_t{0} - (word >> 63);
                product_high ^= factor_high & mask;
                product_low ^= factor_low & mask;
                word <<= 1;
                const uint64_t reduction = uint64_t{0} - (factor_low & 1);
                factor_low = (factor_low >> 1) | (factor_high << 63);
                factor_high = (factor_high >> 1) ^
                              (uint64_t{0xe100000000000000} & reduction);
            }
        }
        high_ = product_high;
        low_ = product_low;
    }
};

Block gcm_initial_counter(const Bytes& nonce) {
    Block counter{};
    copy_n(nonce.begin(), 12, counter.begin());
    counter.back() = 1;
    return counter;
}

// Only the rightmost 32 bits carry, in big-endian order, modulo 2^32.
void gcm_inc32(Block& counter) {
    for (size_t i = counter.size(); i > 12; --i) {
        counter[i - 1] = static_cast<Byte>(counter[i - 1] + 1u);
        if (counter[i - 1] != 0) break;
    }
}

void gcm_crypt(const AES& aes, const Byte* input, size_t length,
               Block counter, Byte* output) {
    while (length != 0) {
        gcm_inc32(counter);
        const Block stream = aes.encrypt(counter);
        const size_t count = min(length, stream.size());
        for (size_t i = 0; i < count; ++i) output[i] = input[i] ^ stream[i];
        input += count;
        output += count;
        length -= count;
    }
}

Block gcm_tag(const AES& aes, const Byte* ciphertext, size_t ciphertext_length,
              const Bytes& associated_data, const Block& initial_counter) {
    Ghash hash(aes.encrypt(Block{}));
    hash.append_padded(associated_data.data(), associated_data.size());
    hash.append_padded(ciphertext, ciphertext_length);
    return xorblock(hash.finish(associated_data.size(), ciphertext_length),
                    aes.encrypt(initial_counter));
}

bool gcm_tag_matches(const Block& expected, const Byte* supplied) {
    unsigned difference = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        difference |= static_cast<unsigned>(expected[i] ^ supplied[i]);
    }
    return difference == 0;
}

}  // namespace

Bytes gcm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
                  const Bytes& associated_data) {
    validate_gcm_nonce(nonce);
    validate_gcm_lengths(plaintext.size(), associated_data.size());
    Bytes result;
    if (plaintext.size() > result.max_size() - 16) {
        throw length_error("AES-GCM ciphertext is too large.");
    }
    result.resize(plaintext.size() + 16);
    const Block initial_counter = gcm_initial_counter(nonce);
    gcm_crypt(aes, plaintext.data(), plaintext.size(), initial_counter, result.data());
    const Block tag = gcm_tag(aes, result.data(), plaintext.size(), associated_data,
                              initial_counter);
    copy(tag.begin(), tag.end(), result.begin() + plaintext.size());
    return result;
}

Bytes gcm_decrypt(const AES& aes, const Bytes& ciphertext_and_tag, const Bytes& nonce,
                  const Bytes& associated_data) {
    validate_gcm_nonce(nonce);
    if (ciphertext_and_tag.size() < 16) {
        throw runtime_error("AES-GCM authentication failed.");
    }
    const size_t ciphertext_length = ciphertext_and_tag.size() - 16;
    validate_gcm_lengths(ciphertext_length, associated_data.size());
    const Block initial_counter = gcm_initial_counter(nonce);
    const Block expected = gcm_tag(aes, ciphertext_and_tag.data(), ciphertext_length,
                                   associated_data, initial_counter);
    if (!gcm_tag_matches(expected, ciphertext_and_tag.data() + ciphertext_length)) {
        throw runtime_error("AES-GCM authentication failed.");
    }
    Bytes plaintext(ciphertext_length);
    gcm_crypt(aes, ciphertext_and_tag.data(), ciphertext_length, initial_counter,
              plaintext.data());
    return plaintext;
}

Bytes gmac(const AES& aes, const Bytes& authenticated_data, const Bytes& nonce) {
    return gcm_encrypt(aes, {}, nonce, authenticated_data);
}

bool gmac_verify(const AES& aes, const Bytes& authenticated_data, const Bytes& tag,
                 const Bytes& nonce) {
    validate_gcm_nonce(nonce);
    validate_gcm_lengths(0, authenticated_data.size());
    if (tag.size() != 16) return false;
    const Block expected = gcm_tag(aes, nullptr, 0, authenticated_data,
                                   gcm_initial_counter(nonce));
    return gcm_tag_matches(expected, tag.data());
}

}  // namespace lab
