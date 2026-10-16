#include "aes_c.h"

#include <algorithm>
#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

using namespace std;

using Key = unique_ptr<aes_modes_key, decltype(&aes_modes_key_destroy)>;
using Buffer = unique_ptr<aes_modes_buffer, decltype(&aes_modes_buffer_destroy)>;

static void require(bool condition, const char* message) {
    if (!condition) throw runtime_error(message);
}

template<size_t Size>
static Key makeKey(const array<uint8_t, Size>& bytes) {
    aes_modes_key* raw = nullptr;
    const int status = aes_modes_key_create(bytes.data(), bytes.size(), &raw);
    Key key(raw, aes_modes_key_destroy);
    require(status == AES_MODES_OK && key != nullptr, "Valid key creation failed.");
    return key;
}

template<size_t Size>
static bool equals(const Buffer& buffer, const array<uint8_t, Size>& expected) {
    if (!buffer || aes_modes_buffer_size(buffer.get()) != expected.size()) return false;
    const uint8_t* data = aes_modes_buffer_data(buffer.get());
    return data != nullptr && equal(expected.begin(), expected.end(), data);
}

int main() {
    try {
        const array<uint8_t, 16> keyBytes = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
        const array<uint8_t, 16> plaintext = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        const array<uint8_t, 16> expected = {
            0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
            0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
        Key key = makeKey(keyBytes);
        aes_modes_buffer* raw = nullptr;
        int status = aes_modes_encrypt_block(key.get(), plaintext.data(), plaintext.size(), &raw);
        Buffer ciphertext(raw, aes_modes_buffer_destroy);
        key.reset();
        require(status == AES_MODES_OK && equals(ciphertext, expected),
                "Result does not remain valid after destroying its key handle.");

        const array<uint8_t, 16> zeroKey{};
        const array<uint8_t, 12> nonce{};
        Key gcmKey = makeKey(zeroKey);
        // Independent GCM vector: binary plaintext contains sixteen zero bytes.
        array<uint8_t, 32> authenticated = {
            0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
            0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78,
            0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
            0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
        raw = nullptr;
        status = aes_modes_gcm_decrypt(gcmKey.get(), authenticated.data(), authenticated.size(),
                                       nonce.data(), nonce.size(), nullptr, 0, &raw);
        Buffer recovered(raw, aes_modes_buffer_destroy);
        require(status == AES_MODES_OK && equals(recovered, zeroKey),
                "Binary plaintext was truncated or incorrectly recovered.");
        authenticated.back() ^= 1;
        raw = nullptr;
        status = aes_modes_gcm_decrypt(gcmKey.get(), authenticated.data(), authenticated.size(),
                                       nonce.data(), nonce.size(), nullptr, 0, &raw);
        Buffer failed(raw, aes_modes_buffer_destroy);
        require(status == AES_MODES_AUTH_FAILED && !failed,
                "Failed authentication released a plaintext result.");
        const string savedError = aes_modes_last_error();
        recovered.reset();
        ciphertext.reset();
        require(savedError == aes_modes_last_error(), "Buffer cleanup erased an error diagnostic.");

        raw = nullptr;
        status = aes_modes_encrypt_block(gcmKey.get(), nullptr, 16, &raw);
        Buffer badInput(raw, aes_modes_buffer_destroy);
        require(status == AES_MODES_INVALID_ARGUMENT && !badInput,
                "NULL input with a nonzero length was accepted.");
        status = aes_modes_encrypt_block(gcmKey.get(), plaintext.data(), plaintext.size(), nullptr);
        require(status == AES_MODES_INVALID_ARGUMENT, "NULL output slot was accepted.");
        raw = nullptr;
        status = aes_modes_ecb_encrypt(gcmKey.get(), nullptr, 0, 2, &raw);
        Buffer badPadding(raw, aes_modes_buffer_destroy);
        require(status == AES_MODES_INVALID_ARGUMENT && !badPadding,
                "A foreign padding flag other than zero/one was accepted.");
        int valid = 1;
        status = aes_modes_cmac_verify(nullptr, nullptr, 0, nullptr, 0, &valid);
        require(status == AES_MODES_INVALID_ARGUMENT && valid == 0,
                "A failed verification left a stale true result.");

        // A successful empty decrypt is an owned empty result, not an auth error.
        const array<uint8_t, 16> emptyTag = {
            0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
            0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a};
        raw = nullptr;
        status = aes_modes_gcm_decrypt(gcmKey.get(), emptyTag.data(), emptyTag.size(),
                                       nonce.data(), nonce.size(), nullptr, 0, &raw);
        Buffer empty(raw, aes_modes_buffer_destroy);
        require(status == AES_MODES_OK && empty && aes_modes_buffer_size(empty.get()) == 0,
                "A valid empty plaintext was confused with failed authentication.");
        require(aes_modes_last_error()[0] == '\0', "A success retained a stale failure diagnostic.");
        cout << "PASS C ABI ownership, binary data, authentication and error boundaries\n";
        return 0;
    } catch (const exception& error) {
        cerr << "FAIL C ABI: " << error.what() << '\n';
        return 1;
    }
}
