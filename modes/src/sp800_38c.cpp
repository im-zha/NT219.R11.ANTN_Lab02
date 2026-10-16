#include "sp800_38c.hpp"

using namespace std;

namespace lab {
namespace {

void validate_ccm_tag_length(int tag_length) {
    if (tag_length < 4 || tag_length > 16 || tag_length % 2 != 0) {
        throw invalid_argument("AES-CCM tag_length must be one of 4, 6, 8, 10, 12, 14, 16.");
    }
}

void validate_ccm_nonce_length(size_t nonce_length) {
    if (nonce_length < 7 || nonce_length > 13) {
        throw invalid_argument("AES-CCM nonce length must be between 7 and 13 bytes.");
    }
}

void validate_ccm_lengths(size_t payload_length, size_t aad_length, size_t q) {
    // Avoid shifting by the width of size_t when the entire size_t range fits.
    if (q < sizeof(size_t) && payload_length >= (size_t{1} << (8 * q))) {
        throw length_error("AES-CCM payload is too long for the nonce length.");
    }
    if constexpr (numeric_limits<size_t>::digits > 64) {
        if (aad_length > numeric_limits<uint64_t>::max()) {
            throw length_error("AES-CCM associated data must contain fewer than 2^64 bytes.");
        }
    }
}

void encode_ccm_integer(Byte* destination, size_t width, uint64_t value) {
    for (size_t i = width; i > 0; --i) {
        destination[i - 1] = static_cast<Byte>(value & 0xff);
        value >>= 8;
    }
}

// Only one pending block is stored. AAD and payload are aligned independently;
// an already complete block never gets an additional all-zero padding block.
class CcmMac {
public:
    CcmMac(const AES& aes, const Block& first_block)
        : aes_(aes), state_(aes.encrypt(first_block)) {}

    void append(const Byte* data, size_t length) {
        while (length > 0) {
            const size_t count = min(length, pending_.size() - used_);
            copy_n(data, count, pending_.begin() + used_);
            data += count;
            length -= count;
            used_ += count;
            if (used_ == pending_.size()) absorb();
        }
    }

    void align() {
        if (used_ != 0) {
            fill(pending_.begin() + used_, pending_.end(), Byte{0});
            absorb();
        }
    }

    const Block& value() const { return state_; }

private:
    const AES& aes_;
    Block state_;
    Block pending_{};
    size_t used_ = 0;

    void absorb() {
        for (size_t i = 0; i < state_.size(); ++i) pending_[i] ^= state_[i];
        state_ = aes_.encrypt(pending_);
        used_ = 0;
    }
};

Block ccm_mac(const AES& aes, const Byte* nonce, size_t nonce_length,
              const Bytes& associated_data, const Bytes& plaintext, int tag_length) {
    const size_t q = 15 - nonce_length;
    Block first{};
    first[0] = static_cast<Byte>((associated_data.empty() ? 0 : 0x40) |
                                (((tag_length - 2) / 2) << 3) | (q - 1));
    copy_n(nonce, nonce_length, first.begin() + 1);
    encode_ccm_integer(first.data() + 16 - q, q, static_cast<uint64_t>(plaintext.size()));
    CcmMac mac(aes, first);

    if (!associated_data.empty()) {
        array<Byte, 10> encoding{};
        const uint64_t length = static_cast<uint64_t>(associated_data.size());
        size_t encoding_length;
        if (length < 0xff00) {
            encoding_length = 2;
            encode_ccm_integer(encoding.data(), 2, length);
        } else if (length < (uint64_t{1} << 32)) {
            encoding_length = 6;
            encoding[0] = 0xff;
            encoding[1] = 0xfe;
            encode_ccm_integer(encoding.data() + 2, 4, length);
        } else {
            encoding_length = 10;
            encoding[0] = 0xff;
            encoding[1] = 0xff;
            encode_ccm_integer(encoding.data() + 2, 8, length);
        }
        mac.append(encoding.data(), encoding_length);
        mac.append(associated_data.data(), associated_data.size());
        mac.align();
    }
    mac.append(plaintext.data(), plaintext.size());
    mac.align();
    return mac.value();
}

Block ccm_counter(const Byte* nonce, size_t nonce_length) {
    Block counter{};
    counter[0] = static_cast<Byte>(14 - nonce_length);
    copy_n(nonce, nonce_length, counter.begin() + 1);
    return counter;
}

void ccm_crypt(const AES& aes, const Byte* input, size_t length,
               Block& counter, size_t q, Byte* output) {
    uint64_t index = 1;
    while (length > 0) {
        encode_ccm_integer(counter.data() + 16 - q, q, index++);
        const Block stream = aes.encrypt(counter);
        const size_t count = min(length, stream.size());
        for (size_t i = 0; i < count; ++i) output[i] = input[i] ^ stream[i];
        input += count;
        output += count;
        length -= count;
    }
}

}  // namespace

// SP 800-38C section 6.1 and Appendix A: ciphertext || (CBC-MAC XOR S0).
Bytes ccm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
                  const Bytes& associated_data, int tag_length) {
    validate_ccm_tag_length(tag_length);
    validate_ccm_nonce_length(nonce.size());
    const size_t q = 15 - nonce.size();
    validate_ccm_lengths(plaintext.size(), associated_data.size(), q);
    const size_t tag_size = static_cast<size_t>(tag_length);
    Bytes result;
    if (plaintext.size() > result.max_size() - tag_size) {
        throw length_error("AES-CCM ciphertext is too large.");
    }
    result.resize(plaintext.size() + tag_size);
    const Block tag = ccm_mac(aes, nonce.data(), nonce.size(), associated_data, plaintext, tag_length);
    Block counter = ccm_counter(nonce.data(), nonce.size());
    const Block tag_mask = aes.encrypt(counter);
    ccm_crypt(aes, plaintext.data(), plaintext.size(), counter, q, result.data());
    for (size_t i = 0; i < tag_size; ++i) {
        result[plaintext.size() + i] = tag[i] ^ tag_mask[i];
    }
    return result;
}

// SP 800-38C section 6.2: plaintext is returned only after tag verification.
Bytes ccm_decrypt(const AES& aes, const Bytes& ciphertext_and_tag, const Bytes& nonce,
                  const Bytes& associated_data, int tag_length) {
    validate_ccm_tag_length(tag_length);
    validate_ccm_nonce_length(nonce.size());
    const size_t tag_size = static_cast<size_t>(tag_length);
    if (ciphertext_and_tag.size() < tag_size) {
        throw runtime_error("AES-CCM authentication failed.");
    }
    const size_t payload_length = ciphertext_and_tag.size() - tag_size;
    const size_t q = 15 - nonce.size();
    validate_ccm_lengths(payload_length, associated_data.size(), q);
    Bytes plaintext(payload_length);
    Block counter = ccm_counter(nonce.data(), nonce.size());
    const Block tag_mask = aes.encrypt(counter);
    ccm_crypt(aes, ciphertext_and_tag.data(), payload_length, counter, q, plaintext.data());
    const Block expected_tag = ccm_mac(aes, nonce.data(), nonce.size(),
                                      associated_data, plaintext, tag_length);
    unsigned difference = 0;
    for (size_t i = 0; i < tag_size; ++i) {
        difference |= static_cast<unsigned>(ciphertext_and_tag[payload_length + i] ^
                                            expected_tag[i] ^ tag_mask[i]);
    }
    if (difference != 0) throw runtime_error("AES-CCM authentication failed.");
    return plaintext;
}

}  // namespace lab
