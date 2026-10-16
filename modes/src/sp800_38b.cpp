#include "sp800_38b.hpp"

using namespace std;

namespace lab {
namespace {

// Multiply a big-endian 128-bit string by x modulo x^128 + x^7 + x^2 + x + 1.
Block double_subkey(const Block& value) {
    Block result;
    unsigned carry = 0;
    for (size_t i = value.size(); i-- > 0;) {
        result[i] = static_cast<Byte>((static_cast<unsigned>(value[i]) << 1) | carry);
        carry = value[i] >> 7;
    }
    result.back() ^= static_cast<Byte>(0x87u * carry);
    return result;
}

Block cmac_block(const AES& aes, const Bytes& message) {
    Block subkey = double_subkey(aes.encrypt(Block{}));
    Block chain{};
    size_t offset = 0;

    // Keep the final complete or partial block for subkey masking. Subtraction
    // avoids overflowing a rounded-up message length or the next-block offset.
    while (message.size() - offset > chain.size()) {
        chain = aes.encrypt(xorblock(chain, block(message, offset)));
        offset += chain.size();
    }

    const size_t remaining = message.size() - offset;
    for (size_t i = 0; i < remaining; ++i) chain[i] ^= message[offset + i];
    if (remaining != chain.size()) {
        // Empty messages also have a padded final block and use K2, not K1.
        chain[remaining] ^= 0x80;
        subkey = double_subkey(subkey);
    }
    return aes.encrypt(xorblock(chain, subkey));
}

}  // namespace

Bytes cmac(const AES& aes, const Bytes& message) {
    const Block tag = cmac_block(aes, message);
    return Bytes(tag.begin(), tag.end());
}

bool cmac_verify(const AES& aes, const Bytes& message, const Bytes& tag) {
    if (tag.size() != AES::BLOCK_SIZE) return false;
    const Block expected = cmac_block(aes, message);
    unsigned difference = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        difference |= static_cast<unsigned>(expected[i] ^ tag[i]);
    }
    return difference == 0;
}

}  // namespace lab
