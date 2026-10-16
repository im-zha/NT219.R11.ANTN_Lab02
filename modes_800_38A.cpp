#include "modes.h"

#include <iostream>

using namespace std;

namespace {
constexpr size_t block_size = Modes38A::BLOCK_SIZE;

size_t checked_size(size_t size, size_t extra) {
    if (extra > numeric_limits<size_t>::max() - size) {
        throw length_error("Mode output is too large.");
    }
    return size + extra;
}

void require_block_multiple(size_t size, const char* message) {
    if (size == 0 || size % block_size != 0) {
        throw invalid_argument(message);
    }
}

void require_iv(const Bytes& value) {
    if (value.size() != block_size) {
        throw invalid_argument("iv must be exactly 16 bytes.");
    }
}

Block load_block(const Bytes& data, size_t offset = 0) {
    Block result;
    copy_n(data.begin() + offset, block_size, result.begin());
    return result;
}

// Form just the current padded block, rather than copying the whole message.
Block plaintext_block(const Bytes& data, size_t offset, Byte padding) {
    Block result;
    const size_t count = offset < data.size()
        ? min(block_size, data.size() - offset) : 0;
    if (count != 0) copy_n(data.begin() + offset, count, result.begin());
    fill(result.begin() + count, result.end(), padding);
    return result;
}

size_t unpadded_size(const Bytes& data) {
    require_block_multiple(data.size(),
        "PKCS#7 padded data must be a non-zero multiple of 16 bytes.");
    const size_t padding = data.back();
    if (padding == 0 || padding > block_size) {
        throw invalid_argument("Invalid PKCS#7 padding length.");
    }
    for (size_t i = data.size() - padding; i < data.size(); ++i) {
        if (data[i] != padding) {
            throw invalid_argument("Invalid PKCS#7 padding bytes.");
        }
    }
    return data.size() - padding;
}

size_t cfb_segment_bytes(int segment_size) {
    if (segment_size <= 0 || segment_size > 128 || segment_size % 8 != 0) {
        throw invalid_argument(
            "segment_size must be one of the byte-aligned sizes from 8 to 128 bits.");
    }
    return static_cast<size_t>(segment_size / 8);
}

Block decryption_iv(const Bytes& ciphertext, const optional<Bytes>& initial_iv,
                    bool has_iv, const char* short_ciphertext_message) {
    if (has_iv) {
        if (ciphertext.size() < block_size) {
            throw invalid_argument(short_ciphertext_message);
        }
        return load_block(ciphertext);
    }
    if (!initial_iv) {
        throw invalid_argument("iv is required when has_iv=False.");
    }
    require_iv(*initial_iv);
    return load_block(*initial_iv);
}

void cfb_transform(const AES& aes, const Bytes& input, size_t input_offset,
                   Bytes& output, size_t output_offset, Block feedback,
                   size_t segment_bytes, bool decrypt) {
    while (input_offset < input.size()) {
        const size_t count = min(segment_bytes, input.size() - input_offset);
        const Block stream = aes.encrypt(feedback);
        for (size_t i = 0; i < count; ++i) {
            output[output_offset + i] = input[input_offset + i] ^ stream[i];
        }
        // Python shifts the register only after a complete segment. In either
        // direction the appended feedback is ciphertext, never plaintext.
        if (count == segment_bytes) {
            for (size_t i = 0; i < block_size - count; ++i) {
                feedback[i] = feedback[i + count];
            }
            for (size_t i = 0; i < count; ++i) {
                feedback[block_size - count + i] = decrypt
                    ? input[input_offset + i] : output[output_offset + i];
            }
        }
        input_offset += count;
        output_offset += count;
    }
}

void ofb_transform(const AES& aes, const Bytes& input, size_t input_offset,
                   Bytes& output, size_t output_offset, Block feedback) {
    while (input_offset < input.size()) {
        feedback = aes.encrypt(feedback);
        const size_t count = min(block_size, input.size() - input_offset);
        for (size_t i = 0; i < count; ++i) {
            output[output_offset + i] = input[input_offset + i] ^ feedback[i];
        }
        input_offset += count;
        output_offset += count;
    }
}

void ctr_transform(const AES& aes, const Bytes& input, size_t input_offset,
                   Bytes& output, size_t output_offset, Block counter) {
    while (input_offset < input.size()) {
        const Block stream = aes.encrypt(counter);
        const size_t count = min(block_size, input.size() - input_offset);
        for (size_t i = 0; i < count; ++i) {
            output[output_offset + i] = input[input_offset + i] ^ stream[i];
        }
        // Big-endian addition modulo 2^128, including carry across all bytes.
        for (size_t i = counter.size(); i > 0; --i) {
            counter[i - 1] = static_cast<Byte>(counter[i - 1] + 1u);
            if (counter[i - 1] != 0) break;
        }
        input_offset += count;
        output_offset += count;
    }
}
}  // namespace

Modes38A::Modes38A(const Bytes& key, bool verbose)
    : aes_(modes_detail::make_aes(key)), verbose_(verbose) {}

Bytes Modes38A::pkcs7_padding(const Bytes& data) {
    const size_t padding = BLOCK_SIZE - data.size() % BLOCK_SIZE;
    Bytes result(checked_size(data.size(), padding), static_cast<Byte>(padding));
    copy(data.begin(), data.end(), result.begin());
    return result;
}

Bytes Modes38A::pkcs7_unpadding(const Bytes& data) {
    const size_t size = unpadded_size(data);
    return Bytes(data.begin(), data.begin() + size);
}

Bytes Modes38A::fresh_iv(const optional<Bytes>& initial_iv) {
    Bytes value = initial_iv ? *initial_iv : modes_detail::random_bytes(BLOCK_SIZE);
    require_iv(value);
    iv = value;
    if (verbose_) {
        constexpr char digits[] = "0123456789abcdef";
        char hexadecimal[2 * BLOCK_SIZE];
        for (size_t i = 0; i < value.size(); ++i) {
            hexadecimal[2 * i] = digits[value[i] >> 4];
            hexadecimal[2 * i + 1] = digits[value[i] & 0x0f];
        }
        cout << "IV: ";
        cout.write(hexadecimal, sizeof hexadecimal);
        cout.put('\n');
    }
    return value;
}

Bytes Modes38A::ecb_encrypt(const Bytes& plaintext, bool pad) const {
    if (!pad) {
        require_block_multiple(plaintext.size(),
            "plaintext length must be a non-zero multiple of 16 bytes.");
    }
    const size_t padding = pad ? BLOCK_SIZE - plaintext.size() % BLOCK_SIZE : 0;
    Bytes result(checked_size(plaintext.size(), padding));
    for (size_t offset = 0; offset < result.size(); offset += BLOCK_SIZE) {
        const Block encrypted = aes_.encrypt(
            plaintext_block(plaintext, offset, static_cast<Byte>(padding)));
        copy(encrypted.begin(), encrypted.end(), result.begin() + offset);
    }
    return result;
}

Bytes Modes38A::ecb_decrypt(const Bytes& ciphertext, bool unpad) const {
    require_block_multiple(ciphertext.size(),
        "ciphertext length must be a non-zero multiple of 16 bytes.");
    Bytes result(ciphertext.size());
    for (size_t offset = 0; offset < ciphertext.size(); offset += BLOCK_SIZE) {
        const Block decrypted = aes_.decrypt(load_block(ciphertext, offset));
        copy(decrypted.begin(), decrypted.end(), result.begin() + offset);
    }
    if (unpad) result.resize(unpadded_size(result));
    return result;
}

Bytes Modes38A::cbc_encrypt(const Bytes& plaintext, const optional<Bytes>& initial_iv,
                            bool prepend_iv, bool pad) {
    const Bytes iv_bytes = fresh_iv(initial_iv);
    if (!pad) {
        require_block_multiple(plaintext.size(),
            "plaintext length must be a non-zero multiple of 16 bytes.");
    }
    const size_t padding = pad ? BLOCK_SIZE - plaintext.size() % BLOCK_SIZE : 0;
    const size_t body_size = checked_size(plaintext.size(), padding);
    const size_t prefix = prepend_iv ? BLOCK_SIZE : 0;
    Bytes result(checked_size(body_size, prefix));
    if (prepend_iv) copy(iv_bytes.begin(), iv_bytes.end(), result.begin());
    Block previous = load_block(iv_bytes);
    for (size_t offset = 0; offset < body_size; offset += BLOCK_SIZE) {
        Block block = plaintext_block(plaintext, offset, static_cast<Byte>(padding));
        for (size_t i = 0; i < BLOCK_SIZE; ++i) block[i] ^= previous[i];
        previous = aes_.encrypt(block);
        copy(previous.begin(), previous.end(), result.begin() + prefix + offset);
    }
    return result;
}

Bytes Modes38A::cbc_decrypt(const Bytes& ciphertext, const optional<Bytes>& initial_iv,
                            bool has_iv, bool unpad) const {
    Block previous;
    size_t offset = 0;
    if (has_iv) {
        if (ciphertext.size() < 2 * BLOCK_SIZE || ciphertext.size() % BLOCK_SIZE != 0) {
            throw invalid_argument(
                "CBC ciphertext with prepended IV must be at least 32 bytes and block-aligned.");
        }
        previous = load_block(ciphertext);
        offset = BLOCK_SIZE;
    } else {
        previous = decryption_iv(ciphertext, initial_iv, false, "");
        require_block_multiple(ciphertext.size(),
            "ciphertext length must be a non-zero multiple of 16 bytes.");
    }
    Bytes result(ciphertext.size() - offset);
    for (size_t output_offset = 0; offset < ciphertext.size();
         offset += BLOCK_SIZE, output_offset += BLOCK_SIZE) {
        const Block block = load_block(ciphertext, offset);
        Block decrypted = aes_.decrypt(block);
        for (size_t i = 0; i < BLOCK_SIZE; ++i) decrypted[i] ^= previous[i];
        copy(decrypted.begin(), decrypted.end(), result.begin() + output_offset);
        previous = block;
    }
    if (unpad) result.resize(unpadded_size(result));
    return result;
}

Bytes Modes38A::cfb_encrypt(const Bytes& plaintext, const optional<Bytes>& initial_iv,
                            int segment_size, bool prepend_iv) {
    const size_t segment_bytes = cfb_segment_bytes(segment_size);
    const Bytes iv_bytes = fresh_iv(initial_iv);
    const size_t prefix = prepend_iv ? BLOCK_SIZE : 0;
    Bytes result(checked_size(plaintext.size(), prefix));
    if (prepend_iv) copy(iv_bytes.begin(), iv_bytes.end(), result.begin());
    cfb_transform(aes_, plaintext, 0, result, prefix, load_block(iv_bytes),
                  segment_bytes, false);
    return result;
}

Bytes Modes38A::cfb_decrypt(const Bytes& ciphertext, const optional<Bytes>& initial_iv,
                            bool has_iv, int segment_size) const {
    const size_t segment_bytes = cfb_segment_bytes(segment_size);
    const Block feedback = decryption_iv(ciphertext, initial_iv, has_iv,
        "CFB ciphertext with prepended IV must be at least 16 bytes.");
    const size_t prefix = has_iv ? BLOCK_SIZE : 0;
    Bytes result(ciphertext.size() - prefix);
    cfb_transform(aes_, ciphertext, prefix, result, 0, feedback, segment_bytes, true);
    return result;
}

Bytes Modes38A::ofb_encrypt(const Bytes& plaintext, const optional<Bytes>& initial_iv,
                            bool prepend_iv) {
    const Bytes iv_bytes = fresh_iv(initial_iv);
    const size_t prefix = prepend_iv ? BLOCK_SIZE : 0;
    Bytes result(checked_size(plaintext.size(), prefix));
    if (prepend_iv) copy(iv_bytes.begin(), iv_bytes.end(), result.begin());
    ofb_transform(aes_, plaintext, 0, result, prefix, load_block(iv_bytes));
    return result;
}

Bytes Modes38A::ofb_decrypt(const Bytes& ciphertext, const optional<Bytes>& initial_iv,
                            bool has_iv) const {
    const Block feedback = decryption_iv(ciphertext, initial_iv, has_iv,
        "OFB ciphertext with prepended IV must be at least 16 bytes.");
    const size_t prefix = has_iv ? BLOCK_SIZE : 0;
    Bytes result(ciphertext.size() - prefix);
    ofb_transform(aes_, ciphertext, prefix, result, 0, feedback);
    return result;
}

Bytes Modes38A::ctr_encrypt(const Bytes& plaintext, const optional<Bytes>& initial_iv,
                            bool prepend_iv) {
    const Bytes iv_bytes = fresh_iv(initial_iv);
    const size_t prefix = prepend_iv ? BLOCK_SIZE : 0;
    Bytes result(checked_size(plaintext.size(), prefix));
    if (prepend_iv) copy(iv_bytes.begin(), iv_bytes.end(), result.begin());
    ctr_transform(aes_, plaintext, 0, result, prefix, load_block(iv_bytes));
    return result;
}

Bytes Modes38A::ctr_decrypt(const Bytes& ciphertext, const optional<Bytes>& initial_iv,
                            bool has_iv) const {
    const Block counter = decryption_iv(ciphertext, initial_iv, has_iv,
        "CTR ciphertext with prepended counter block must be at least 16 bytes.");
    const size_t prefix = has_iv ? BLOCK_SIZE : 0;
    Bytes result(ciphertext.size() - prefix);
    ctr_transform(aes_, ciphertext, prefix, result, 0, counter);
    return result;
}
