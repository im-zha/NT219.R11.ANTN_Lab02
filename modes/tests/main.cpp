#include "sp800_38a.hpp"
#include "sp800_38c.hpp"
#include "sp800_38b.hpp"
#include "sp800_38d.hpp"
#include "sp800_38e.hpp"
#include "sp800_38f.hpp"
#include "rfc8452_gcm_siv.hpp"

#include <array>
#include <exception>
#include <iostream>

using namespace std;

static Bytes hexToBytes(string_view hex) {
    if (hex.size() % 2 != 0) throw invalid_argument("Hex input must have an even length.");
    const auto digit = [](char ch) -> unsigned {
        if (ch >= '0' && ch <= '9') return static_cast<unsigned>(ch - '0');
        if (ch >= 'a' && ch <= 'f') return static_cast<unsigned>(ch - 'a' + 10);
        if (ch >= 'A' && ch <= 'F') return static_cast<unsigned>(ch - 'A' + 10);
        throw invalid_argument("Invalid hexadecimal digit.");
    };
    Bytes bytes(hex.size() / 2);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<Byte>((digit(hex[2 * i]) << 4) | digit(hex[2 * i + 1]));
    }
    return bytes;
}

// Independent answers for the same AES-128 key used by the Appendix F vectors.
static bool checkCounterBoundary(const AES& aes) {
    Bytes counter(16, 0xff);
    const Bytes expectedOne = hexToBytes("8af2860142f786f409307c1a3f7eaaac");
    if (lab::ctr_crypt(aes, Bytes(16, 0), counter) != expectedOne) return false;
    try {
        lab::ctr_crypt(aes, Bytes(17, 0), counter);
        return false;
    } catch (const overflow_error&) {
    }

    counter.back() = 0xfe;
    const Bytes expectedTwo = hexToBytes(
        "d1b714b6fbf5fff1289aee2a4c4eeda3"
        "8af2860142f786f409307c1a3f7eaaac");
    if (lab::ctr_crypt(aes, Bytes(32, 0), counter) != expectedTwo) return false;
    try {
        lab::ctr_crypt(aes, Bytes(33, 0), counter);
        return false;
    } catch (const overflow_error&) {
    }
    return true;
}

static bool rejectsCcm(const AES& aes, const Bytes& message, const Bytes& nonce, const Bytes& aad) {
    try {
        (void)lab::ccm_decrypt(aes, message, nonce, aad, 8);
    } catch (const runtime_error&) {
        return true;
    }
    return false;
}

static bool runCcmVector() {
    // RFC 3610, Packet Vector #1: eight cleartext header bytes are AAD.
    const Bytes key = hexToBytes("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    const AES aes(key);
    const Bytes nonce = hexToBytes("00000003020100a0a1a2a3a4a5");
    const Bytes aad = hexToBytes("0001020304050607");
    const Bytes plaintext = hexToBytes("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    const Bytes expected = hexToBytes(
        "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"
        "17e8d12cfdf926e0");
    const Bytes computed = lab::ccm_encrypt(aes, plaintext, nonce, aad, 8);
    const bool sizeMatches = computed.size() == expected.size();
    const bool ciphertextPassed = sizeMatches &&
        equal(expected.begin(), expected.begin() + plaintext.size(), computed.begin()) &&
        lab::ccm_decrypt(aes, expected, nonce, aad, 8) == plaintext;
    bool tagPassed = sizeMatches &&
        equal(expected.begin() + plaintext.size(), expected.end(), computed.begin() + plaintext.size());

    Bytes tampered = expected;
    for (size_t offset : {size_t{0}, tampered.size() - 1}) {
        tampered[offset] ^= 1;
        tagPassed &= rejectsCcm(aes, tampered, nonce, aad);
        tampered[offset] ^= 1;
    }
    Bytes wrongAad = aad;
    wrongAad[0] ^= 1;
    tagPassed &= rejectsCcm(aes, expected, nonce, wrongAad);
    Bytes wrongNonce = nonce;
    wrongNonce[0] ^= 1;
    tagPassed &= rejectsCcm(aes, expected, wrongNonce, aad);
    Bytes wrongKey = key;
    wrongKey[0] ^= 1;
    tagPassed &= rejectsCcm(AES(wrongKey), expected, nonce, aad);

    cout << (ciphertextPassed ? "PASS " : "FAIL ") << "CCM RFC3610 ct\n";
    cout << (tagPassed ? "PASS " : "FAIL ") << "CCM RFC3610 tag\n";
    return ciphertextPassed && tagPassed;
}

static bool report(const char* name, bool passed) {
    cout << (passed ? "PASS " : "FAIL ") << name << '\n';
    return passed;
}

template <class Action>
static bool rejectsAuthentication(const Action& action) {
    try {
        (void)action();
    } catch (const runtime_error&) {
        return true;
    }
    return false;
}

static bool runGcmVectors() {
    // NIST AES_GCM.pdf, GCM-AES128 Examples #1, #3 and #5.
    const AES aes(hexToBytes("feffe9928665731c6d6a8f9467308308"));
    const Bytes nonce = hexToBytes("cafebabefacedbaddecaf888");
    const Bytes emptyTag = hexToBytes("3247184b3c4f69a44dbcd22887bbb418");
    const bool emptyPassed = lab::gcm_encrypt(aes, {}, nonce) == emptyTag &&
        lab::gcm_decrypt(aes, emptyTag, nonce).empty();

    const Bytes plaintext = hexToBytes(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39");
    const Bytes aad = hexToBytes("3ad77bb40d7a3660a89ecaf32466ef97f5d3d585");
    const Bytes expected = hexToBytes(
        "42831ec2217774244b7221b784d0d49c"
        "e3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091"
        "f07c2528eea2fca1211f905e1b6a881b");
    const Bytes computed = lab::gcm_encrypt(aes, plaintext, nonce, aad);
    const bool sizeMatches = computed.size() == expected.size();
    const bool ciphertextPassed = sizeMatches &&
        equal(expected.begin(), expected.begin() + plaintext.size(), computed.begin()) &&
        lab::gcm_decrypt(aes, expected, nonce, aad) == plaintext;
    bool tagPassed = sizeMatches &&
        equal(expected.begin() + plaintext.size(), expected.end(), computed.begin() + plaintext.size());

    Bytes tampered = expected;
    for (size_t offset : {size_t{0}, tampered.size() - 1}) {
        tampered[offset] ^= 1;
        tagPassed &= rejectsAuthentication([&] { return lab::gcm_decrypt(aes, tampered, nonce, aad); });
        tampered[offset] ^= 1;
    }
    Bytes wrongAad = aad;
    wrongAad[0] ^= 1;
    tagPassed &= rejectsAuthentication([&] { return lab::gcm_decrypt(aes, expected, nonce, wrongAad); });

    const Bytes gmacData = hexToBytes(
        "3ad77bb40d7a3660a89ecaf32466ef97f"
        "5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4");
    const Bytes gmacTag = hexToBytes("5f91d77123ef5eb9997913849b8dc1e9");
    tagPassed &= lab::gmac(aes, gmacData, nonce) == gmacTag &&
        lab::gmac_verify(aes, gmacData, gmacTag, nonce);
    Bytes wrongTag = gmacTag;
    wrongTag.back() ^= 1;
    tagPassed &= !lab::gmac_verify(aes, gmacData, wrongTag, nonce);

    bool passed = report("GCM empty", emptyPassed);
    passed &= report("GCM ct", ciphertextPassed);
    passed &= report("GCM tag", tagPassed);
    return passed;
}

static bool runCmacVectors() {
    // RFC 4493, Section 4, Examples 1 and 2.
    const AES aes(hexToBytes("2b7e151628aed2a6abf7158809cf4f3c"));
    const Bytes emptyTag = hexToBytes("bb1d6929e95937287fa37d129b756746");
    const Bytes message = hexToBytes("6bc1bee22e409f96e93d7e117393172a");
    const Bytes blockTag = hexToBytes("070a16b46b4d4144f79bdd9dd04a287c");
    const bool emptyPassed = lab::cmac(aes, {}) == emptyTag && lab::cmac_verify(aes, {}, emptyTag);
    bool blockPassed = lab::cmac(aes, message) == blockTag && lab::cmac_verify(aes, message, blockTag);
    Bytes wrongTag = blockTag;
    wrongTag.back() ^= 1;
    blockPassed &= !lab::cmac_verify(aes, message, wrongTag);
    bool passed = report("CMAC empty", emptyPassed);
    passed &= report("CMAC 16B", blockPassed);
    return passed;
}

static bool runKeyWrapVectors() {
    // RFC 3394 Section 4.1; RFC 5649 Section 6 (multi- and single-semiblock KWP).
    const AES kwAes(hexToBytes("000102030405060708090a0b0c0d0e0f"));
    const Bytes keyData = hexToBytes("00112233445566778899aabbccddeeff");
    const Bytes wrapped = hexToBytes("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
    bool kwPassed = lab::kw_wrap(kwAes, keyData) == wrapped &&
        lab::kw_unwrap(kwAes, wrapped) == keyData;
    Bytes tampered = wrapped;
    tampered.front() ^= 1;
    kwPassed &= rejectsAuthentication([&] { return lab::kw_unwrap(kwAes, tampered); });

    const AES kwpAes(hexToBytes("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"));
    const Bytes longKey = hexToBytes("c37b7e6492584340bed12207808941155068f738");
    const Bytes longWrapped = hexToBytes(
        "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");
    const Bytes shortKey = hexToBytes("466f7250617369");
    const Bytes shortWrapped = hexToBytes("afbeb0f07dfbf5419200f2ccb50bb24f");
    bool kwpPassed = lab::kwp_wrap(kwpAes, longKey) == longWrapped &&
        lab::kwp_unwrap(kwpAes, longWrapped) == longKey &&
        lab::kwp_wrap(kwpAes, shortKey) == shortWrapped &&
        lab::kwp_unwrap(kwpAes, shortWrapped) == shortKey;
    tampered = shortWrapped;
    tampered.back() ^= 1;
    kwpPassed &= rejectsAuthentication([&] { return lab::kwp_unwrap(kwpAes, tampered); });
    bool passed = report("KW RFC3394", kwPassed);
    passed &= report("KWP RFC5649", kwpPassed);
    return passed;
}

static bool runXtsVector() {
    // NIST XTSGenAES128.rsp, hex-tweak format, ENCRYPT COUNT 1 (IEEE 1619 XTS).
    const Bytes key = hexToBytes(
        "a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f");
    const Bytes tweak = hexToBytes("4faef7117cda59c66e4b92013e768ad5");
    const Bytes plaintext = hexToBytes("ebabce95b14d3c8d6fb350390790311c");
    const Bytes expected = hexToBytes("778ae8b43cb98d5a825081d5be471c63");
    return report("XTS IEEE block", lab::xts_encrypt(key, plaintext, tweak) == expected &&
        lab::xts_decrypt(key, expected, tweak) == plaintext);
}

static bool runGcmSivVectors() {
    // RFC 8452 Appendix C.1, first two AES-128-GCM-SIV vectors.
    const Bytes key = hexToBytes("01000000000000000000000000000000");
    const Bytes nonce = hexToBytes("030000000000000000000000");
    const Bytes emptyTag = hexToBytes("dc20e2d83f25705bb49e439eca56de25");
    const bool emptyPassed = lab::gcm_siv_encrypt(key, {}, nonce) == emptyTag &&
        lab::gcm_siv_decrypt(key, emptyTag, nonce).empty();
    const Bytes plaintext = hexToBytes("0100000000000000");
    const Bytes expected = hexToBytes("b5d839330ac7b786578782fff6013b815b287c22493a364c");
    bool dataPassed = lab::gcm_siv_encrypt(key, plaintext, nonce) == expected &&
        lab::gcm_siv_decrypt(key, expected, nonce) == plaintext;
    Bytes tampered = expected;
    for (size_t offset : {size_t{0}, tampered.size() - 1}) {
        tampered[offset] ^= 1;
        dataPassed &= rejectsAuthentication([&] { return lab::gcm_siv_decrypt(key, tampered, nonce); });
        tampered[offset] ^= 1;
    }
    bool passed = report("GCM-SIV128 empty", emptyPassed);
    passed &= report("GCM-SIV128 8 byte ct+tag", dataPassed);
    return passed;
}

enum class Mode { ECB, CBC, CFB128, CFB8, OFB, CTR };

struct TestVector {
    const char* name;
    Mode mode;
    const char* ciphertext;
};

int main() {
    try {
        // NIST SP 800-38A, Appendix F: AES-128 examples, without padding/IV prefix.
        const Bytes key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        const Bytes iv = hexToBytes("000102030405060708090a0b0c0d0e0f");
        const Bytes counter = hexToBytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const Bytes plaintext = hexToBytes(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710");
        // F.3.7/F.3.8 list 18 one-byte segments, not four 16-byte blocks.
        const Bytes cfb8Plaintext = hexToBytes("6bc1bee22e409f96e93d7e117393172aae2d");
        constexpr array<TestVector, 6> vectors = {{
            {"ECB", Mode::ECB,
             "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
             "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"},
            {"CBC", Mode::CBC,
             "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
             "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"},
            {"CFB128", Mode::CFB128,
             "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
             "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6"},
            {"CFB8", Mode::CFB8, "3b79424c9c0dd436bace9e0ed4586a4f32b9"},
            {"OFB", Mode::OFB,
             "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
             "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"},
            {"CTR", Mode::CTR,
             "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
             "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"}
        }};

        const AES aes(key);
        bool allPassed = true;
        for (const TestVector& tv : vectors) {
            const Bytes& input = tv.mode == Mode::CFB8 ? cfb8Plaintext : plaintext;
            const Bytes expected = hexToBytes(tv.ciphertext);
            Bytes encrypted;
            Bytes decrypted;
            bool boundaryPassed = true;
            // Decrypt the NIST ciphertext independently of our encryption result.
            switch (tv.mode) {
            case Mode::ECB:
                encrypted = lab::ecb_encrypt(aes, input, false);
                decrypted = lab::ecb_decrypt(aes, expected, false);
                break;
            case Mode::CBC:
                encrypted = lab::cbc_encrypt(aes, input, iv, false);
                decrypted = lab::cbc_decrypt(aes, expected, iv, false);
                break;
            case Mode::CFB128:
                encrypted = lab::cfb_encrypt(aes, input, iv, 128);
                decrypted = lab::cfb_decrypt(aes, expected, iv, 128);
                break;
            case Mode::CFB8:
                encrypted = lab::cfb_encrypt(aes, input, iv, 8);
                decrypted = lab::cfb_decrypt(aes, expected, iv, 8);
                break;
            case Mode::OFB:
                encrypted = lab::ofb_crypt(aes, input, iv);
                decrypted = lab::ofb_crypt(aes, expected, iv);
                break;
            case Mode::CTR:
                encrypted = lab::ctr_crypt(aes, input, counter);
                decrypted = lab::ctr_crypt(aes, expected, counter);
                boundaryPassed = checkCounterBoundary(aes);
                break;
            }
            const bool passed = encrypted == expected && decrypted == input && boundaryPassed;
            cout << (passed ? "PASS " : "FAIL ") << tv.name << '\n';
            allPassed &= passed;
        }
        allPassed &= runGcmVectors();
        allPassed &= runCmacVectors();
        allPassed &= runKeyWrapVectors();
        allPassed &= runCcmVector();
        allPassed &= runXtsVector();
        allPassed &= runGcmSivVectors();
        cout << (allPassed ? "ALL 18 VECTORS PASS" : "SOME VECTORS FAIL") << '\n';
        return allPassed ? 0 : 1;
    } catch (const exception& error) {
        cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
