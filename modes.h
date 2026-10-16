#ifndef AES_MODES_H
#define AES_MODES_H

#include "AES.h"
#include <limits>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace std;

using Bytes = vector<Byte>;

// Include this header and link the required modes_800_38A.cpp / modes_800_38C.cpp.
// Do not link AES.cpp into a program with its own main: it is the Task 1 demo.

// Python bytes are represented by Bytes. Convert text explicitly so binary
// plaintext/ciphertext (including zero bytes) never undergo implicit decoding.
inline Bytes utf8_to_bytes(string_view text) {
    if (text.empty()) return {};
    const auto* first = reinterpret_cast<const Byte*>(text.data());
    return Bytes(first, first + text.size());
}

inline string bytes_to_utf8(const Bytes& data) {
    size_t i = 0;
    while (i < data.size()) {
        const Byte first = data[i++];
        if (first < 0x80) continue;
        size_t remaining;
        Byte lower = 0x80;
        Byte upper = 0xbf;
        if (first >= 0xc2 && first <= 0xdf) {
            remaining = 1;
        } else if (first >= 0xe0 && first <= 0xef) {
            remaining = 2;
            if (first == 0xe0) lower = 0xa0;
            if (first == 0xed) upper = 0x9f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            remaining = 3;
            if (first == 0xf0) lower = 0x90;
            if (first == 0xf4) upper = 0x8f;
        } else {
            throw invalid_argument("Invalid UTF-8 data.");
        }
        if (remaining > data.size() - i || data[i] < lower || data[i] > upper) {
            throw invalid_argument("Invalid UTF-8 data.");
        }
        ++i;
        for (size_t j = 1; j < remaining; ++j, ++i) {
            if (data[i] < 0x80 || data[i] > 0xbf) {
                throw invalid_argument("Invalid UTF-8 data.");
            }
        }
    }
    if (data.empty()) return {};
    return string(reinterpret_cast<const char*>(data.data()), data.size());
}

// The reversible 1-bit padding here is the same as binary_to_bytes in modes.py;
// it is separate from the PKCS#7 padding used by ECB/CBC.
inline Bytes binary_to_bytes(string_view bits) {
    if (bits.substr(0, 2) == "0b") bits.remove_prefix(2);
    Bytes result(bits.size() / 8 + 1, 0);
    for (size_t i = 0; i < bits.size(); ++i) {
        if (bits[i] != '0' && bits[i] != '1') {
            throw invalid_argument("Binary input must contain only 0 and 1.");
        }
        if (bits[i] == '1') {
            result[i / 8] |= static_cast<Byte>(1u << (7 - i % 8));
        }
    }
    result[bits.size() / 8] |= static_cast<Byte>(1u << (7 - bits.size() % 8));
    return result;
}

inline string bytes_to_binary(const Bytes& data) {
    size_t end = data.size();
    while (end > 0 && data[end - 1] == 0) --end;
    if (end == 0) {
        throw invalid_argument("Invalid reversible binary padding: missing marker bit.");
    }
    unsigned trailing = 0;
    while ((data[end - 1] & (1u << trailing)) == 0) ++trailing;
    if (end - 1 > (numeric_limits<size_t>::max() - 7) / 8) {
        throw length_error("Binary output is too large.");
    }
    const size_t marker = (end - 1) * 8 + 7 - trailing;
    string result = "0b";
    if (marker > result.max_size() - 2) throw length_error("Binary output is too large.");
    result.reserve(marker + 2);
    for (size_t i = 0; i < marker; ++i) {
        result.push_back((data[i / 8] & (1u << (7 - i % 8))) != 0 ? '1' : '0');
    }
    return result;
}

namespace modes_detail {
inline AES make_aes(const Bytes& key) {
    if (key.size() == 16) {
        array<Byte, 16> fixed;
        copy_n(key.begin(), fixed.size(), fixed.begin());
        return AES(fixed);
    }
    if (key.size() == 24) {
        array<Byte, 24> fixed;
        copy_n(key.begin(), fixed.size(), fixed.begin());
        return AES(fixed);
    }
    if (key.size() == 32) {
        array<Byte, 32> fixed;
        copy_n(key.begin(), fixed.size(), fixed.begin());
        return AES(fixed);
    }
    throw invalid_argument("Invalid AES key length. Use 16, 24 or 32 bytes.");
}

inline Bytes random_bytes(size_t count) {
    // C++ does not give random_device a portable cryptographic guarantee.
    // Refuse a source that reports no entropy; never substitute a PRNG.
    random_device source;
    if (source.entropy() == 0) {
        throw runtime_error("random_device reports no entropy; supply an explicit IV/nonce.");
    }
    uniform_int_distribution<unsigned> distribution(0, 255);
    Bytes result(count);
    for (Byte& value : result) value = static_cast<Byte>(distribution(source));
    return result;
}
}  // namespace modes_detail

// SP 800-38A portion of modes.py. Decryption returns bytes; bytes_to_utf8 is
// the explicit C++ replacement for output_encoding="utf-8" in Python.
class Modes38A {
public:
    static constexpr size_t BLOCK_SIZE = 16;
    explicit Modes38A(const Bytes& key, bool verbose = false);
    optional<Bytes> iv;  // Last IV/counter generated or supplied for encryption.

    static Bytes pkcs7_padding(const Bytes& data);
    static Bytes pkcs7_unpadding(const Bytes& data);

    Bytes ecb_encrypt(const Bytes& plaintext, bool pad = true) const;
    Bytes ecb_decrypt(const Bytes& ciphertext, bool unpad = true) const;
    Bytes cbc_encrypt(const Bytes& plaintext, const optional<Bytes>& initial_iv = nullopt,
                      bool prepend_iv = true, bool pad = true);
    Bytes cbc_decrypt(const Bytes& ciphertext, const optional<Bytes>& initial_iv = nullopt,
                      bool has_iv = true, bool unpad = true) const;
    Bytes cfb_encrypt(const Bytes& plaintext, const optional<Bytes>& initial_iv = nullopt,
                      int segment_size = 128, bool prepend_iv = true);
    Bytes cfb_decrypt(const Bytes& ciphertext, const optional<Bytes>& initial_iv = nullopt,
                      bool has_iv = true, int segment_size = 128) const;
    Bytes ofb_encrypt(const Bytes& plaintext, const optional<Bytes>& initial_iv = nullopt,
                      bool prepend_iv = true);
    Bytes ofb_decrypt(const Bytes& ciphertext, const optional<Bytes>& initial_iv = nullopt,
                      bool has_iv = true) const;
    Bytes ctr_encrypt(const Bytes& plaintext, const optional<Bytes>& initial_iv = nullopt,
                      bool prepend_iv = true);
    Bytes ctr_decrypt(const Bytes& ciphertext, const optional<Bytes>& initial_iv = nullopt,
                      bool has_iv = true) const;

private:
    AES aes_;
    bool verbose_;
    Bytes fresh_iv(const optional<Bytes>& initial_iv);
};

// SP 800-38C portion of modes.py. Body format is ciphertext || encrypted tag;
// nonce prefixing, nonce_length and tag_length retain the Python defaults.
class Modes38C {
public:
    explicit Modes38C(const Bytes& key);
    Bytes ccm_encrypt(const Bytes& plaintext, const Bytes& associated_data = {},
                      const optional<Bytes>& nonce = nullopt, int tag_length = 16,
                      bool prepend_nonce = true) const;
    Bytes ccm_decrypt(const Bytes& ciphertext_and_tag, const Bytes& associated_data = {},
                      const optional<Bytes>& nonce = nullopt, bool has_nonce = true,
                      int nonce_length = 13, int tag_length = 16) const;

private:
    AES aes_;
};

#endif
