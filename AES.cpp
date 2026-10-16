#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

// Task 1: standalone translation of mypackages/AES.py; no modes or padding.
// Build: g++ -std=c++17 -O2 AES.cpp -o AES
// Algorithm: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
class AES {
public:
    using Byte = uint8_t;
    static constexpr size_t BLOCK_SIZE = 16;
    using Block = array<Byte, BLOCK_SIZE>;
    using Word = array<Byte, 4>;
    using State = array<Word, 4>;  // state[row][column]

    AES(const vector<Byte>& key, int keyLengthBits = 0) {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
            throw invalid_argument("AES keys must contain 16, 24 or 32 bytes.");
        }
        keyLength_ = keyLengthBits == 0 ? static_cast<int>(key.size() * 8) : keyLengthBits;
        if (keyLength_ != 128 && keyLength_ != 192 && keyLength_ != 256) {
            throw invalid_argument("Invalid AES key length. Use 128, 192 or 256 bits.");
        }
        if (key.size() != static_cast<size_t>(keyLength_ / 8)) {
            throw invalid_argument("AES key size does not match keyLengthBits.");
        }
        key_ = key;
        numRounds_ = keyLength_ / 32 + 6;
        keyExpansion();
    }

    Block encrypt(const Block& plaintext) const {
        State state = bytesToState(plaintext);
        addRoundKey(state, 0);
        for (int round = 1; round < numRounds_; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }
        // The final round has no MixColumns (FIPS 197, Algorithm 1).
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, numRounds_);
        return stateToBytes(state);
    }

    Block decrypt(const Block& ciphertext) const {
        State state = bytesToState(ciphertext);
        addRoundKey(state, numRounds_);
        for (int round = numRounds_ - 1; round > 0; --round) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);
        return stateToBytes(state);
    }

private:
    vector<Byte> key_;
    int keyLength_ = 0;
    int numRounds_ = 0;
    vector<Word> roundKeys_;  // expanded words w[i]

    inline static constexpr array<Byte, 256> S_BOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    inline static constexpr array<Byte, 256> INV_S_BOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    inline static constexpr array<Word, 10> RCON = {{
        {{0x01, 0, 0, 0}}, {{0x02, 0, 0, 0}},
        {{0x04, 0, 0, 0}}, {{0x08, 0, 0, 0}},
        {{0x10, 0, 0, 0}}, {{0x20, 0, 0, 0}},
        {{0x40, 0, 0, 0}}, {{0x80, 0, 0, 0}},
        {{0x1b, 0, 0, 0}}, {{0x36, 0, 0, 0}}
    }};

    static Byte gmul(Byte a, Byte b) {
        Byte product = 0;
        while (b != 0) {
            if ((b & 1u) != 0) product ^= a;
            b = static_cast<Byte>(b >> 1);
            if (b != 0) {
                a = static_cast<Byte>((static_cast<unsigned>(a) << 1) ^
                                     ((a & 0x80u) != 0 ? 0x1bu : 0u));
            }
        }
        return product;
    }

    static State bytesToState(const Block& block) {
        State state;
        for (size_t column = 0; column < 4; ++column) {
            for (size_t row = 0; row < 4; ++row) {
                state[row][column] = block[4 * column + row];
            }
        }
        return state;
    }

    static Block stateToBytes(const State& state) {
        Block block;
        for (size_t column = 0; column < 4; ++column) {
            for (size_t row = 0; row < 4; ++row) {
                block[4 * column + row] = state[row][column];
            }
        }
        return block;
    }

    static void subBytes(State& state) {
        for (auto& row : state) {
            for (Byte& value : row) value = S_BOX[value];
        }
    }

    static void invSubBytes(State& state) {
        for (auto& row : state) {
            for (Byte& value : row) value = INV_S_BOX[value];
        }
    }

    static void shiftRows(State& state) {
        rotate(state[1].begin(), state[1].begin() + 1, state[1].end());
        rotate(state[2].begin(), state[2].begin() + 2, state[2].end());
        rotate(state[3].begin(), state[3].begin() + 3, state[3].end());
    }

    static void invShiftRows(State& state) {
        rotate(state[1].rbegin(), state[1].rbegin() + 1, state[1].rend());
        rotate(state[2].rbegin(), state[2].rbegin() + 2, state[2].rend());
        rotate(state[3].rbegin(), state[3].rbegin() + 3, state[3].rend());
    }

    static void mixColumns(State& state) {
        for (size_t c = 0; c < 4; ++c) {
            const Byte s0 = state[0][c], s1 = state[1][c];
            const Byte s2 = state[2][c], s3 = state[3][c];
            state[0][c] = gmul(s0, 0x02) ^ gmul(s1, 0x03) ^ s2 ^ s3;
            state[1][c] = s0 ^ gmul(s1, 0x02) ^ gmul(s2, 0x03) ^ s3;
            state[2][c] = s0 ^ s1 ^ gmul(s2, 0x02) ^ gmul(s3, 0x03);
            state[3][c] = gmul(s0, 0x03) ^ s1 ^ s2 ^ gmul(s3, 0x02);
        }
    }

    static void invMixColumns(State& state) {
        for (size_t c = 0; c < 4; ++c) {
            const Byte s0 = state[0][c], s1 = state[1][c];
            const Byte s2 = state[2][c], s3 = state[3][c];
            state[0][c] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
            state[1][c] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
            state[2][c] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
            state[3][c] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
        }
    }

    void addRoundKey(State& state, int round) const {
        const size_t first = 4 * static_cast<size_t>(round);
        for (size_t column = 0; column < 4; ++column) {
            for (size_t row = 0; row < 4; ++row) {
                state[row][column] ^= roundKeys_[first + column][row];
            }
        }
    }

    static Word subWord(Word word) {
        for (Byte& value : word) value = S_BOX[value];
        return word;
    }

    static Word rotWord(Word word) {
        rotate(word.begin(), word.begin() + 1, word.end());
        return word;
    }

    void keyExpansion() {
        const size_t nk = key_.size() / 4;
        roundKeys_.resize(4 * static_cast<size_t>(numRounds_ + 1));
        for (size_t i = 0; i < nk; ++i) {
            for (size_t j = 0; j < 4; ++j) roundKeys_[i][j] = key_[4 * i + j];
        }
        for (size_t i = nk; i < roundKeys_.size(); ++i) {
            Word temp = roundKeys_[i - 1];
            if (i % nk == 0) {
                temp = subWord(rotWord(temp));
                for (size_t j = 0; j < 4; ++j) temp[j] ^= RCON[i / nk - 1][j];
            } else if (nk == 8 && i % nk == 4) {
                temp = subWord(temp);
            }
            for (size_t j = 0; j < 4; ++j) {
                roundKeys_[i][j] = roundKeys_[i - nk][j] ^ temp[j];
            }
        }
    }
};

static unsigned hexDigit(char ch) {
    if (ch >= '0' && ch <= '9') return static_cast<unsigned>(ch - '0');
    if (ch >= 'a' && ch <= 'f') return static_cast<unsigned>(ch - 'a' + 10);
    if (ch >= 'A' && ch <= 'F') return static_cast<unsigned>(ch - 'A' + 10);
    throw invalid_argument("Invalid hexadecimal digit.");
}

static vector<uint8_t> hexToBytes(const string& hex) {
    if (hex.size() % 2 != 0) throw invalid_argument("Hex input must have an even length.");
    vector<uint8_t> bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>((hexDigit(hex[2 * i]) << 4) | hexDigit(hex[2 * i + 1]));
    }
    return bytes;
}

static AES::Block hexToBlock(const string& hex) {
    if (hex.size() != 2 * AES::BLOCK_SIZE) {
        throw invalid_argument("An AES block must contain 32 hexadecimal digits.");
    }
    AES::Block block;
    for (size_t i = 0; i < block.size(); ++i) {
        block[i] = static_cast<AES::Byte>((hexDigit(hex[2 * i]) << 4) | hexDigit(hex[2 * i + 1]));
    }
    return block;
}

static string blockToHex(const AES::Block& block) {
    constexpr char digits[] = "0123456789abcdef";
    string hex(2 * block.size(), '0');
    for (size_t i = 0; i < block.size(); ++i) {
        hex[2 * i] = digits[block[i] >> 4];
        hex[2 * i + 1] = digits[block[i] & 0x0f];
    }
    return hex;
}

struct TestVector {
    const char* name;
    const char* key;
    const char* plaintext;
    const char* expected;
};

static bool runKnownAnswerTest(const TestVector& tv) {
    const AES aes(hexToBytes(tv.key));
    const AES::Block plaintext = hexToBlock(tv.plaintext);
    const AES::Block expected = hexToBlock(tv.expected);
    const AES::Block computed = aes.encrypt(plaintext);
    const AES::Block decrypted = aes.decrypt(expected);
    const bool encryptPassed = computed == expected;
    const bool decryptPassed = decrypted == plaintext;
    cout << tv.name << " Known-Answer Test\n"
         << "  Key       : " << tv.key << '\n'
         << "  Plaintext : " << tv.plaintext << '\n'
         << "  Expected  : " << tv.expected << '\n'
         << "  Computed  : " << blockToHex(computed) << '\n'
         << "  Decrypted : " << blockToHex(decrypted) << '\n'
         << "  Encrypt   : " << (encryptPassed ? "PASS" : "FAIL") << '\n'
         << "  Decrypt   : " << (decryptPassed ? "PASS" : "FAIL") << "\n\n";
    return encryptPassed && decryptPassed;
}

int main() {
    try {
        constexpr array<TestVector, 3> vectors = {{
            {"AES-128", "000102030405060708090a0b0c0d0e0f",
             "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"},
            {"AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617",
             "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"},
            {"AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"}
        }};
        bool passed = true;
        for (const TestVector& tv : vectors) passed &= runKnownAnswerTest(tv);
        return passed ? 0 : 1;
    } catch (const exception& error) {
        cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
