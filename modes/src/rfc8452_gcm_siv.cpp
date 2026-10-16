#include "rfc8452_gcm_siv.hpp"

#include <cstdint>

using namespace std;

namespace lab {
namespace {

constexpr uint64_t max_input_bytes = uint64_t{1} << 36;
constexpr uint64_t ghash_reduction = uint64_t{0xe1} << 56;

void check_parameters(const Bytes& key, const Bytes& nonce, size_t payload_size,
                      size_t aad_size) {
    if (key.size() != 16 && key.size() != 32) {
        throw invalid_argument("AES-GCM-SIV key must contain 16 or 32 bytes.");
    }
    if (nonce.size() != 12) {
        throw invalid_argument("AES-GCM-SIV nonce must contain exactly 12 bytes.");
    }
    if (payload_size > max_input_bytes || aad_size > max_input_bytes) {
        throw length_error("AES-GCM-SIV plaintext and AAD are limited to 2^36 bytes each.");
    }
}

uint64_t load_le64(const Byte* bytes) {
    uint64_t result = 0;
    for (size_t i = 0; i < 8; ++i) {
        result |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    }
    return result;
}

void store_le64(Byte* bytes, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        bytes[i] = static_cast<Byte>(value >> (8 * i));
    }
}

// RFC 8452 Appendix A:
// POLYVAL(H, X...) = reverse(GHASH(mulX_GHASH(reverse(H)), reverse(X)...)).
// State and key below are GHASH's big-endian high/low words. Loading the
// original bytes little-endian in swapped halves performs the byte reversal.
// Transforming H by mulX is essential: POLYVAL uses dot(a,b), not just a*b.
class Polyval {
public:
    explicit Polyval(const Block& authentication_key)
        : key_high_(load_le64(authentication_key.data() + 8)),
          key_low_(load_le64(authentication_key.data())) {
        const uint64_t reduction_mask = uint64_t{0} - (key_low_ & 1);
        key_low_ = (key_low_ >> 1) | (key_high_ << 63);
        key_high_ = (key_high_ >> 1) ^ (ghash_reduction & reduction_mask);
    }

    void update(const Byte* input) {
        const array<uint64_t, 2> words{
            high_ ^ load_le64(input + 8), low_ ^ load_le64(input)};
        uint64_t product_high = 0;
        uint64_t product_low = 0;
        uint64_t factor_high = key_high_;
        uint64_t factor_low = key_low_;
        for (uint64_t word : words) {
            for (unsigned bit = 0; bit < 64; ++bit) {
                const uint64_t bit_mask = uint64_t{0} - (word >> 63);
                product_high ^= factor_high & bit_mask;
                product_low ^= factor_low & bit_mask;
                word <<= 1;
                const uint64_t reduction_mask = uint64_t{0} - (factor_low & 1);
                factor_low = (factor_low >> 1) | (factor_high << 63);
                factor_high = (factor_high >> 1) ^ (ghash_reduction & reduction_mask);
            }
        }
        high_ = product_high;
        low_ = product_low;
    }

    void update_padded(const Bytes& input) {
        size_t offset = 0;
        while (input.size() - offset >= 16) {
            update(input.data() + offset);
            offset += 16;
        }
        if (offset != input.size()) {
            Block final_block{};
            copy_n(input.data() + offset, input.size() - offset, final_block.begin());
            update(final_block.data());
        }
    }

    Block result() const {
        Block output{};
        store_le64(output.data(), low_);
        store_le64(output.data() + 8, high_);
        return output;
    }

private:
    uint64_t key_high_;
    uint64_t key_low_;
    uint64_t high_ = 0;
    uint64_t low_ = 0;
};

AES derive_cipher(const Bytes& key, const Bytes& nonce, Block& authentication_key) {
    const AES master(key);
    Bytes encryption_key(key.size());
    Block derivation_block{};
    copy(nonce.begin(), nonce.end(), derivation_block.begin() + 4);
    const size_t block_count = 2 + key.size() / 8;
    for (size_t counter = 0; counter < block_count; ++counter) {
        // Counters 0..3 or 0..5 fit in the low byte of the uint32 little-endian field.
        derivation_block[0] = static_cast<Byte>(counter);
        const Block material = master.encrypt(derivation_block);
        if (counter < 2) {
            copy_n(material.begin(), 8, authentication_key.begin() + counter * 8);
        } else {
            copy_n(material.begin(), 8, encryption_key.begin() + (counter - 2) * 8);
        }
    }
    return AES(encryption_key);
}

Block make_tag(const AES& cipher, const Block& authentication_key, const Bytes& nonce,
               const Bytes& associated_data, const Bytes& plaintext) {
    Polyval hash(authentication_key);
    hash.update_padded(associated_data);
    hash.update_padded(plaintext);
    Block lengths{};
    store_le64(lengths.data(), static_cast<uint64_t>(associated_data.size()) * 8);
    store_le64(lengths.data() + 8, static_cast<uint64_t>(plaintext.size()) * 8);
    hash.update(lengths.data());
    Block synthetic_iv = hash.result();
    for (size_t i = 0; i < nonce.size(); ++i) synthetic_iv[i] ^= nonce[i];
    synthetic_iv[15] &= 0x7f;
    return cipher.encrypt(synthetic_iv);
}

void crypt(const AES& cipher, const Bytes& input, size_t payload_size,
           const Block& tag, Bytes& output) {
    Block counter = tag;
    counter[15] |= 0x80;
    size_t offset = 0;
    while (offset < payload_size) {
        const Block stream = cipher.encrypt(counter);
        const size_t count = min(size_t{16}, payload_size - offset);
        for (size_t i = 0; i < count; ++i) {
            output[offset + i] = input[offset + i] ^ stream[i];
        }
        offset += count;
        // Only the first four bytes are incremented, modulo 2^32. Wrapping is
        // required by RFC 8452, including its Appendix C.3 counter-wrap vectors.
        if (offset < payload_size) {
            for (size_t i = 0; i < 4; ++i) {
                counter[i] = static_cast<Byte>(counter[i] + 1u);
                if (counter[i] != 0) break;
            }
        }
    }
}

}  // namespace

Bytes gcm_siv_encrypt(const Bytes& key, const Bytes& plaintext, const Bytes& nonce,
                      const Bytes& associated_data) {
    check_parameters(key, nonce, plaintext.size(), associated_data.size());
    Bytes output;
    if (plaintext.size() > output.max_size() - 16) {
        throw length_error("AES-GCM-SIV ciphertext is too large.");
    }
    Block authentication_key{};
    const AES cipher = derive_cipher(key, nonce, authentication_key);
    const Block tag = make_tag(cipher, authentication_key, nonce, associated_data, plaintext);
    output.resize(plaintext.size() + tag.size());
    crypt(cipher, plaintext, plaintext.size(), tag, output);
    copy(tag.begin(), tag.end(), output.begin() + plaintext.size());
    return output;
}

Bytes gcm_siv_decrypt(const Bytes& key, const Bytes& ciphertext_and_tag, const Bytes& nonce,
                      const Bytes& associated_data) {
    if (ciphertext_and_tag.size() < 16) {
        throw invalid_argument("AES-GCM-SIV ciphertext must include a 16-byte tag.");
    }
    const size_t payload_size = ciphertext_and_tag.size() - 16;
    check_parameters(key, nonce, payload_size, associated_data.size());
    Block authentication_key{};
    const AES cipher = derive_cipher(key, nonce, authentication_key);
    const Block tag = block(ciphertext_and_tag, payload_size);
    Bytes plaintext(payload_size);
    crypt(cipher, ciphertext_and_tag, payload_size, tag, plaintext);
    const Block expected = make_tag(cipher, authentication_key, nonce, associated_data, plaintext);
    unsigned difference = 0;
    for (size_t i = 0; i < tag.size(); ++i) difference |= expected[i] ^ tag[i];
    if (difference != 0) throw runtime_error("AES-GCM-SIV authentication failed.");
    return plaintext;
}

}  // namespace lab
