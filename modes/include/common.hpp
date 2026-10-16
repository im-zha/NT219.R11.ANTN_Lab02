#ifndef AES_MODES_COMMON_HPP
#define AES_MODES_COMMON_HPP

#include "aes.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

using namespace std;

using Byte = AES::Byte;
using Block = AES::Block;
using Bytes = vector<Byte>;

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

// Helpers required by the teacher's 38A source; padding remains strict PKCS#7.
namespace lab {

inline void check_iv(const Bytes& iv) {
    if (iv.size() != 16) throw invalid_argument("IV must contain exactly 16 bytes.");
}

inline void check_aligned(const Bytes& data) {
    if (data.empty() || data.size() % 16 != 0) {
        throw invalid_argument("Data must be a non-zero multiple of 16 bytes.");
    }
}

inline Block block(const Bytes& data, size_t offset = 0) {
    if (offset > data.size() || data.size() - offset < 16) {
        throw invalid_argument("A block requires 16 bytes from the given offset.");
    }
    Block result;
    copy_n(data.begin() + offset, result.size(), result.begin());
    return result;
}

inline Block xorblock(const Block& left, const Block& right) {
    Block result;
    for (size_t i = 0; i < result.size(); ++i) result[i] = left[i] ^ right[i];
    return result;
}

inline void append(Bytes& out, const Block& value) {
    out.insert(out.end(), value.begin(), value.end());
}

inline Bytes pad(const Bytes& data) {
    const size_t amount = 16 - data.size() % 16;
    if (amount > numeric_limits<size_t>::max() - data.size()) {
        throw length_error("Padded data is too large.");
    }
    Bytes out;
    out.reserve(data.size() + amount);
    out.insert(out.end(), data.begin(), data.end());
    out.insert(out.end(), amount, static_cast<Byte>(amount));
    return out;
}

inline Bytes unpad(Bytes data) {
    check_aligned(data);
    const size_t amount = data.back();
    if (amount == 0 || amount > 16) throw invalid_argument("Invalid PKCS#7 padding length.");
    for (size_t i = data.size() - amount; i < data.size(); ++i) {
        if (data[i] != amount) throw invalid_argument("Invalid PKCS#7 padding bytes.");
    }
    data.resize(data.size() - amount);
    return data;
}

}  // namespace lab

#endif
