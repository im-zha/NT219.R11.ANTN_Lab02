#include "sp800_38a.hpp"

using namespace std;

namespace lab {
namespace {
constexpr size_t block_size = 16;

size_t checked_size(size_t size, size_t extra) {
    if (extra > numeric_limits<size_t>::max() - size) {
        throw length_error("Mode output is too large.");
    }
    return size + extra;
}

// Build only the current padded block, without copying the whole plaintext.
Block plaintext_block(const Bytes& data, size_t offset, Byte padding) {
    Block result;
    const size_t count = offset < data.size() ? min(block_size, data.size() - offset) : 0;
    if (count != 0) copy_n(data.begin() + offset, count, result.begin());
    fill(result.begin() + count, result.end(), padding);
    return result;
}
}  // namespace

Bytes ecb_encrypt(const AES& aes, const Bytes& in, bool padding) {
    if (!padding) check_aligned(in);
    const size_t amount = padding ? block_size - in.size() % block_size : 0;
    const size_t size = checked_size(in.size(), amount);
    Bytes out;
    out.reserve(size);
    for (size_t i = 0; i < size; i += block_size) {
        append(out, aes.encrypt(plaintext_block(in, i, static_cast<Byte>(amount))));
    }
    return out;
}

Bytes ecb_decrypt(const AES& aes, const Bytes& d, bool padding) {
    check_aligned(d);
    Bytes out;
    out.reserve(d.size());
    for (size_t i = 0; i < d.size(); i += block_size) {
        append(out, aes.decrypt(block(d, i)));
    }
    if (padding) return unpad(move(out));
    return out;
}

Bytes cbc_encrypt(const AES& aes, const Bytes& in, const Bytes& iv, bool padding) {
    check_iv(iv);
    if (!padding) check_aligned(in);
    const size_t amount = padding ? block_size - in.size() % block_size : 0;
    const size_t size = checked_size(in.size(), amount);
    Bytes out;
    out.reserve(size);
    Block previous = block(iv);
    for (size_t i = 0; i < size; i += block_size) {
        previous = aes.encrypt(xorblock(plaintext_block(in, i, static_cast<Byte>(amount)), previous));
        append(out, previous);
    }
    return out;
}

Bytes cbc_decrypt(const AES& aes, const Bytes& d, const Bytes& iv, bool padding) {
    check_iv(iv);
    check_aligned(d);
    Bytes out;
    out.reserve(d.size());
    Block previous = block(iv);
    for (size_t i = 0; i < d.size(); i += block_size) {
        const Block current = block(d, i);
        append(out, xorblock(aes.decrypt(current), previous));
        previous = current;
    }
    if (padding) return unpad(move(out));
    return out;
}

static Bytes cfb(const AES& aes, const Bytes& d, const Bytes& iv, int segbits, bool encrypt) {
    check_iv(iv);
    if (segbits < 8 || segbits > 128 || segbits % 8 != 0) {
        throw invalid_argument("CFB segment bits must be 8..128 byte aligned");
    }
    const size_t n = static_cast<size_t>(segbits / 8);
    Block reg = block(iv);
    Bytes out;
    out.reserve(d.size());
    for (size_t i = 0; i < d.size();) {
        const Block stream = aes.encrypt(reg);
        const size_t take = min(n, d.size() - i);
        for (size_t j = 0; j < take; ++j) out.push_back(d[i + j] ^ stream[j]);
        if (take == n && take < d.size() - i) {
            for (size_t j = 0; j < block_size - n; ++j) reg[j] = reg[j + n];
            for (size_t j = 0; j < n; ++j) reg[block_size - n + j] = encrypt ? out[i + j] : d[i + j];
        }
        i += take;
    }
    return out;
}

Bytes cfb_encrypt(const AES& aes, const Bytes& d, const Bytes& iv, int segbits) {
    return cfb(aes, d, iv, segbits, true);
}

Bytes cfb_decrypt(const AES& aes, const Bytes& d, const Bytes& iv, int segbits) {
    return cfb(aes, d, iv, segbits, false);
}

Bytes ofb_crypt(const AES& aes, const Bytes& d, const Bytes& iv) {
    check_iv(iv);
    Block feed = block(iv);
    Bytes out;
    out.reserve(d.size());
    for (size_t i = 0; i < d.size();) {
        feed = aes.encrypt(feed);
        const size_t take = min(block_size, d.size() - i);
        for (size_t j = 0; j < take; ++j) out.push_back(d[i + j] ^ feed[j]);
        i += take;
    }
    return out;
}

Bytes ctr_crypt(const AES& aes, const Bytes& d, const Bytes& iv) {
    check_iv(iv);
    Block counter = block(iv);
    Bytes out;
    out.reserve(d.size());
    for (size_t i = 0; i < d.size();) {
        const Block stream = aes.encrypt(counter);
        const size_t take = min(block_size, d.size() - i);
        for (size_t j = 0; j < take; ++j) out.push_back(d[i + j] ^ stream[j]);
        i += take;
        if (i < d.size()) {
            bool wrapped = true;
            for (size_t j = block_size; j > 0; --j) {
                counter[j - 1] = static_cast<Byte>(counter[j - 1] + 1u);
                if (counter[j - 1] != 0) {
                    wrapped = false;
                    break;
                }
            }
            if (wrapped) throw overflow_error("CTR counter wrapped");
        }
    }
    return out;
}

}  // namespace lab
