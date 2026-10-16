#include "sp800_38e.hpp"

using namespace std;

namespace lab {
namespace {

void validate_xts(const Bytes& key, const Bytes& data, const Bytes& tweak) {
    if (key.size() != 32 && key.size() != 64) {
        throw invalid_argument("XTS key must contain 32 or 64 bytes.");
    }
    const size_t half = key.size() / 2;
    if (equal(key.begin(), key.begin() + half, key.begin() + half)) {
        throw invalid_argument("XTS data and tweak keys must be different.");
    }
    if (tweak.size() != 16) {
        throw invalid_argument("XTS tweak must contain exactly 16 bytes.");
    }
    if (data.size() < 16) {
        throw invalid_argument("XTS data unit must contain at least 16 bytes.");
    }
    constexpr size_t max_data_unit = size_t{16} * (size_t{1} << 20);
    if (data.size() > max_data_unit) {
        throw length_error("XTS data unit exceeds 2^20 AES blocks.");
    }
}

// IEEE 1619 numbers the field coefficients little-endian within the byte string.
void advance_tweak(Block& tweak) {
    unsigned carry = 0;
    for (Byte& value : tweak) {
        const unsigned next = value >> 7;
        value = static_cast<Byte>((static_cast<unsigned>(value) << 1) | carry);
        carry = next;
    }
    tweak[0] ^= static_cast<Byte>(0x87u & (0u - carry));
}

template<bool Encrypt>
Block xex(const AES& aes, const Block& input, const Block& tweak) {
    const Block masked = xorblock(input, tweak);
    if constexpr (Encrypt) {
        return xorblock(aes.encrypt(masked), tweak);
    } else {
        return xorblock(aes.decrypt(masked), tweak);
    }
}

template<bool Encrypt>
Bytes transform_xts(const Bytes& key, const Bytes& data, const Bytes& tweak) {
    validate_xts(key, data, tweak);
    const size_t half = key.size() / 2;
    // AES's vector-key constructor requires the two small key slices; schedules
    // are expanded once, never reconstructed while processing the data unit.
    const AES data_aes(Bytes(key.begin(), key.begin() + half));
    const AES tweak_aes(Bytes(key.begin() + half, key.end()));
    Block current = tweak_aes.encrypt(block(tweak));
    Bytes output(data.size());

    const size_t partial = data.size() % 16;
    const size_t ordinary_end = data.size() - partial - (partial != 0 ? 16 : 0);
    for (size_t offset = 0; offset < ordinary_end; offset += 16) {
        const Block result = xex<Encrypt>(data_aes, block(data, offset), current);
        copy(result.begin(), result.end(), output.begin() + offset);
        if (offset + 16 < data.size()) advance_tweak(current);
    }
    if (partial == 0) return output;

    // current belongs to the final complete plaintext block; next belongs to
    // the padded partial plaintext block, which is stored as a complete block.
    Block next = current;
    advance_tweak(next);
    const size_t tail = ordinary_end + 16;
    if constexpr (Encrypt) {
        Block stolen = xex<true>(data_aes, block(data, ordinary_end), current);
        copy_n(stolen.begin(), partial, output.begin() + tail);
        copy_n(data.begin() + tail, partial, stolen.begin());
        const Block result = xex<true>(data_aes, stolen, next);
        copy(result.begin(), result.end(), output.begin() + ordinary_end);
    } else {
        Block reconstructed = xex<false>(data_aes, block(data, ordinary_end), next);
        copy_n(reconstructed.begin(), partial, output.begin() + tail);
        copy_n(data.begin() + tail, partial, reconstructed.begin());
        const Block result = xex<false>(data_aes, reconstructed, current);
        copy(result.begin(), result.end(), output.begin() + ordinary_end);
    }
    return output;
}

}  // namespace

Bytes xts_encrypt(const Bytes& key, const Bytes& plaintext, const Bytes& tweak) {
    return transform_xts<true>(key, plaintext, tweak);
}

Bytes xts_decrypt(const Bytes& key, const Bytes& ciphertext, const Bytes& tweak) {
    return transform_xts<false>(key, ciphertext, tweak);
}

}  // namespace lab
