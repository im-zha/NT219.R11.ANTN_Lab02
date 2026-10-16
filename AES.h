// AES block primitive shared by Task 1 and the SP 800-38A / SP 800-38C code.
#ifndef AES_H
#define AES_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

using namespace std;

using Byte = uint8_t;
using Block = array<Byte, 16>;
using Word = array<Byte, 4>;
using State = array<Word, 4>;  // state[row][column]

class AES {
public:
    // Fixed-size arrays enforce valid key sizes without a heap allocation.
    template <size_t KeyBytes>
    explicit AES(const array<Byte, KeyBytes>& key)
        : num_rounds_(static_cast<int>(KeyBytes / 4) + 6) {
        static_assert(KeyBytes == 16 || KeyBytes == 24 || KeyBytes == 32,
                      "AES keys must contain 16, 24 or 32 bytes.");
        key_expansion(key);
    }

    int num_rounds() const noexcept { return num_rounds_; }

    Block encrypt(const Block& plaintext) const {
        State state = bytes_to_state(plaintext);
        add_round_key(state, 0);

        for (int round = 1; round < num_rounds_; ++round) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }

        // The final encryption round MUST NOT call MixColumns.
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, num_rounds_);
        return state_to_bytes(state);
    }

    Block decrypt(const Block& ciphertext) const {
        State state = bytes_to_state(ciphertext);
        add_round_key(state, num_rounds_);

        // A signed counter avoids unsigned underflow when counting backwards.
        for (int round = num_rounds_ - 1; round > 0; --round) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, round);
            inv_mix_columns(state);
        }

        // The final inverse round MUST NOT call InvMixColumns.
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, 0);
        return state_to_bytes(state);
    }

private:
    int num_rounds_;
    // AES-256 needs at most 60 words. KeyExpansion initializes every used word.
    array<Word, 60> round_keys_;

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

    // Only the first byte of each Rcon word is nonzero.
    inline static constexpr array<Byte, 10> RCON = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    static State bytes_to_state(const Block& block) {
        State state;
        for (size_t row = 0; row < 4; ++row) {
            for (size_t column = 0; column < 4; ++column) {
                state[row][column] = block[4 * column + row];
            }
        }
        return state;
    }

    static Block state_to_bytes(const State& state) {
        Block block;
        for (size_t column = 0; column < 4; ++column) {
            for (size_t row = 0; row < 4; ++row) {
                block[4 * column + row] = state[row][column];
            }
        }
        return block;
    }

    static void sub_bytes(State& state) {
        for (auto& row : state) {
            for (Byte& value : row) value = S_BOX[value];
        }
    }

    static void inv_sub_bytes(State& state) {
        for (auto& row : state) {
            for (Byte& value : row) value = INV_S_BOX[value];
        }
    }

    static void shift_rows(State& state) {
        rotate(state[1].begin(), state[1].begin() + 1, state[1].end());
        rotate(state[2].begin(), state[2].begin() + 2, state[2].end());
        rotate(state[3].begin(), state[3].begin() + 3, state[3].end());
    }

    static void inv_shift_rows(State& state) {
        rotate(state[1].begin(), state[1].begin() + 3, state[1].end());
        rotate(state[2].begin(), state[2].begin() + 2, state[2].end());
        rotate(state[3].begin(), state[3].begin() + 1, state[3].end());
    }

    // Multiply by x in GF(2^8), modulo x^8 + x^4 + x^3 + x + 1.
    static Byte xtime(Byte value) {
        return static_cast<Byte>((static_cast<unsigned>(value) << 1) ^
                                 ((value & 0x80u) != 0 ? 0x1bu : 0u));
    }

    static Byte gmul(Byte a, Byte b) {
        Byte product = 0;
        while (b != 0) {
            if ((b & 1u) != 0) product ^= a;
            b = static_cast<Byte>(b >> 1);
            if (b != 0) a = xtime(a);
        }
        return product;
    }

    static void mix_columns(State& state) {
        for (size_t column = 0; column < 4; ++column) {
            // Capture the original column before overwriting any of its bytes.
            const Byte a = state[0][column];
            const Byte b = state[1][column];
            const Byte c = state[2][column];
            const Byte d = state[3][column];
            const Byte all = static_cast<Byte>(a ^ b ^ c ^ d);
            // Equivalent to the FIPS matrix with coefficients 02, 03, 01, 01.
            state[0][column] = static_cast<Byte>(a ^ all ^ xtime(static_cast<Byte>(a ^ b)));
            state[1][column] = static_cast<Byte>(b ^ all ^ xtime(static_cast<Byte>(b ^ c)));
            state[2][column] = static_cast<Byte>(c ^ all ^ xtime(static_cast<Byte>(c ^ d)));
            state[3][column] = static_cast<Byte>(d ^ all ^ xtime(static_cast<Byte>(d ^ a)));
        }
    }

    static void inv_mix_columns(State& state) {
        for (size_t column = 0; column < 4; ++column) {
            const Byte a = state[0][column];
            const Byte b = state[1][column];
            const Byte c = state[2][column];
            const Byte d = state[3][column];
            state[0][column] = static_cast<Byte>(gmul(a, 0x0e) ^ gmul(b, 0x0b) ^ gmul(c, 0x0d) ^ gmul(d, 0x09));
            state[1][column] = static_cast<Byte>(gmul(a, 0x09) ^ gmul(b, 0x0e) ^ gmul(c, 0x0b) ^ gmul(d, 0x0d));
            state[2][column] = static_cast<Byte>(gmul(a, 0x0d) ^ gmul(b, 0x09) ^ gmul(c, 0x0e) ^ gmul(d, 0x0b));
            state[3][column] = static_cast<Byte>(gmul(a, 0x0b) ^ gmul(b, 0x0d) ^ gmul(c, 0x09) ^ gmul(d, 0x0e));
        }
    }

    void add_round_key(State& state, int round) const {
        const auto first_word = 4 * static_cast<size_t>(round);
        for (size_t column = 0; column < 4; ++column) {
            for (size_t row = 0; row < 4; ++row) {
                state[row][column] ^= round_keys_[first_word + column][row];
            }
        }
    }

    static void sub_word(Word& word) {
        for (Byte& value : word) value = S_BOX[value];
    }

    static void rot_word(Word& word) {
        rotate(word.begin(), word.begin() + 1, word.end());
    }

    template <size_t KeyBytes>
    void key_expansion(const array<Byte, KeyBytes>& key) {
        constexpr size_t nk = KeyBytes / 4;
        const auto total_words = 4 * static_cast<size_t>(num_rounds_ + 1);
        for (size_t i = 0; i < nk; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                round_keys_[i][j] = key[4 * i + j];
            }
        }
        for (size_t i = nk; i < total_words; ++i) {
            Word temp = round_keys_[i - 1];
            if (i % nk == 0) {
                rot_word(temp);
                sub_word(temp);
                temp[0] ^= RCON[i / nk - 1];
            } else if (nk == 8 && i % nk == 4) {
                // The additional SubWord step is required for AES-256.
                sub_word(temp);
            }
            for (size_t j = 0; j < 4; ++j) {
                round_keys_[i][j] = static_cast<Byte>(round_keys_[i - nk][j] ^ temp[j]);
            }
        }
    }

};
#endif
