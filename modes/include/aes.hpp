#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

// Library contract from Materials/aes.hpp. trace only controls diagnostic output;
// it does not change block results. Task 1's standalone AES.cpp is separate.
class AES {
public:
    static constexpr size_t BLOCK_SIZE = 16;
    using Byte = uint8_t;
    using Block = array<Byte, BLOCK_SIZE>;
    using Word = array<Byte, 4>;
    using State = array<array<Byte, 4>, 4>; // state[row][column]

    AES(const vector<Byte>& key, int keyLengthBits = 0);
    Block encrypt(const Block& plaintext, bool trace = false) const;
    Block decrypt(const Block& ciphertext, bool trace = false) const;
    void printAllRoundKeys() const;

private:
    vector<Byte> key_;
    int keyLength_ = 0;
    int numRounds_ = 0;
    vector<Word> roundKeys_;

    static const array<Byte, 256> S_BOX;
    static const array<Byte, 256> INV_S_BOX;
    static const array<Word, 10> RCON;
    static Byte gmul(Byte a, Byte b);
    static State bytesToState(const Block& block);
    static Block stateToBytes(const State& state);
    static void subBytes(State& state);
    static void invSubBytes(State& state);
    static void shiftRows(State& state);
    static void invShiftRows(State& state);
    static void mixColumns(State& state);
    static void invMixColumns(State& state);
    void addRoundKey(State& state, int round) const;
    static Word rotWord(Word w);
    static Word subWord(Word w);
    vector<Word> keyExpansion(const vector<Byte>& key) const;
    static string byteToHex(Byte b);
    void printRoundKey(int round) const;
    static void printState(const string& label, const State& state);
};
