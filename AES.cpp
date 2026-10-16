#include "AES.h"
#include <array>
#include <cstddef>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string_view>

using namespace std;


static void print_byte(ostream& out, Byte value) {
    constexpr char hex[] = "0123456789abcdef";
    out.put(hex[value >> 4]);
    out.put(hex[value & 0x0f]);
}

template <size_t N>
static void print_hex(ostream& out, const array<Byte, N>& bytes) {
    for (Byte value : bytes) {
        print_byte(out, value);
    }
}

// Two hexadecimal digits represent one byte, not two text characters.
static unsigned hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') return static_cast<unsigned>(ch - '0');
    if (ch >= 'a' && ch <= 'f') return static_cast<unsigned>(ch - 'a' + 10);
    if (ch >= 'A' && ch <= 'F') return static_cast<unsigned>(ch - 'A' + 10);
    throw invalid_argument("Invalid hexadecimal digit.");
}

template <size_t N>
static array<Byte, N> from_hex(string_view hex) {
    if (hex.size() != 2 * N) {
        throw invalid_argument("Unexpected hexadecimal input length.");
    }
    array<Byte, N> bytes;
    for (size_t i = 0; i < N; ++i) {
        bytes[i] = static_cast<Byte>((hex_digit(hex[2 * i]) << 4) |
                                    hex_digit(hex[2 * i + 1]));
    }
    return bytes;
}


template <size_t KeyBytes>
static bool run_example(const char* title, string_view key_hex,
                        string_view plaintext_hex, string_view expected_hex) {
    const auto key = from_hex<KeyBytes>(key_hex);
    const Block plaintext = from_hex<16>(plaintext_hex);
    const Block expected = from_hex<16>(expected_hex);
    const AES aes(key);

    cout << title << " Known-Answer Test\n"
              << "  Key       : ";
    print_hex(cout, key);
    cout << "\n  Plaintext : ";
    print_hex(cout, plaintext);
    cout << "\n  Expected  : ";
    print_hex(cout, expected);
    cout << '\n';

    const Block ciphertext = aes.encrypt(plaintext);
    // Decrypt an independent known ciphertext, not just our encryption output.
    const Block decrypted = aes.decrypt(expected);
    const bool encrypt_passed = ciphertext == expected;
    const bool decrypt_passed = decrypted == plaintext;

    cout << "  Computed  : ";
    print_hex(cout, ciphertext);
    cout << "\n  Decrypted : ";
    print_hex(cout, decrypted);
    cout << "\n  Encrypt   : " << (encrypt_passed ? "PASS" : "FAIL")
              << "\n  Decrypt   : " << (decrypt_passed ? "PASS" : "FAIL")
              << "\n\n";
    return encrypt_passed && decrypt_passed;
}

int main() {
    try {
        constexpr string_view plaintext = "00112233445566778899aabbccddeeff";
        bool all_passed = true;
        all_passed &= run_example<16>(
            "AES-128", "000102030405060708090a0b0c0d0e0f", plaintext,
            "69c4e0d86a7b0430d8cdb78070b4c55a");
        all_passed &= run_example<24>(
            "AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617", plaintext,
            "dda97ca4864cdfe06eaf70a0ec0d7191");
        all_passed &= run_example<32>(
            "AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", plaintext,
            "8ea2b7ca516745bfeafc49904b496089");
        return all_passed ? 0 : 1;
    } catch (const exception& error) {
        cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
