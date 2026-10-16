#include <aes.hpp>
#include <iomanip>
#include <iostream>
#include <vector>

using namespace std;

int main() {
    // FIPS 197, Appendix C.1: AES-128 with a 128-bit plaintext block.
    const vector<AES::Byte> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const AES::Block plaintext = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const AES::Block expected_ciphertext = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };

    const AES aes(key, 128);
    const AES::Block ciphertext = aes.encrypt(plaintext);
    // Decrypt the published ciphertext independently, not the encryption result.
    const AES::Block decrypted = aes.decrypt(expected_ciphertext);

    cout << "AES-128 ciphertext: " << hex << setfill('0');
    for (const auto byte : ciphertext) {
        cout << setw(2) << static_cast<unsigned int>(byte);
    }
    cout << '\n';
    if (ciphertext != expected_ciphertext || decrypted != plaintext) {
        cerr << "FAIL: FIPS 197 AES-128 encryption/decryption known-answer test\n";
        return 1;
    }
    cout << "PASS: FIPS 197 AES-128 encryption/decryption known-answer test\n";
    return 0;
}
