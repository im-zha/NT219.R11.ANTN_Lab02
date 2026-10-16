"""Run Task 4 native AES checks: python3 task4/main.py PATH_TO_LIBRARY.

Build first with ``cmake -S . -B build -DAES_LIBRARY_TYPE=BOTH`` followed by
``cmake --build build``. Supply the actual .so/.dll file, not a directory.
Only Python's standard library is required. Fixed keys, IVs and nonces below
are public test fixtures, NOT production nonce-generation examples; never
reuse GCM/CCM nonces, OFB IVs or CTR sequences under a production key.
"""

import sys

from aes_modes import AuthenticationError, Library


def check(label, actual, expected):
    if actual != expected:
        render = lambda value: value.hex() if isinstance(value, bytes) else repr(value)
        raise RuntimeError("{}: got {}, expected {}".format(label, render(actual), render(expected)))
    detail = " = " + actual.hex() if isinstance(actual, bytes) else ""
    print("PASS {}{}".format(label, detail))


def reject_forgery(label, decrypt, ciphertext):
    forged = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    try:
        decrypt(forged)
    except AuthenticationError:
        print("PASS {} forged-tag rejection".format(label))
    else:
        raise RuntimeError(label + " accepted a forged tag")


def run(library):
    # FIPS 197 Appendix C: independent expected ciphertexts for all key sizes.
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    vectors = (
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"),
    )
    for key_hex, expected_hex in vectors:
        key = bytes.fromhex(key_hex)
        with library.aes(key) as aes:
            expected = bytes.fromhex(expected_hex)
            check("AES-{} FIPS encryption".format(len(key) * 8), aes.encrypt_block(plaintext), expected)
            check("AES-{} FIPS decryption".format(len(key) * 8), aes.decrypt_block(expected), plaintext)

    # NIST SP 800-38D, one zero block with a zero AES-128 key and 96-bit IV.
    with library.aes(bytes(16)) as aes:
        nonce = bytes(12)
        expected = bytes.fromhex(
            "0388dace60b6a392f328c2b971b2fe78"
            "ab6e47d42cec13bdf53a67b21257bddf")
        encrypted = aes.gcm_encrypt(bytes(16), nonce)
        check("GCM known-answer ciphertext || tag", encrypted, expected)
        check("GCM decryption", aes.gcm_decrypt(expected, nonce), bytes(16))
        reject_forgery("GCM", lambda data: aes.gcm_decrypt(data, nonce), encrypted)

    # Binary payload and AAD deliberately contain embedded NULs.
    data = b"AES ctypes\x00binary message\xff\x00end"
    aad = b"header\x00metadata"
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    with library.aes(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")) as aes:
        for label, encrypt, decrypt in (
            ("ECB PKCS#7", aes.ecb_encrypt, aes.ecb_decrypt),
            ("CBC PKCS#7", lambda value: aes.cbc_encrypt(value, iv),
             lambda value: aes.cbc_decrypt(value, iv)),
            ("CFB-128", lambda value: aes.cfb_encrypt(value, iv),
             lambda value: aes.cfb_decrypt(value, iv)),
            ("CFB-8", lambda value: aes.cfb_encrypt(value, iv, segment_bits=8),
             lambda value: aes.cfb_decrypt(value, iv, segment_bits=8)),
            ("OFB", lambda value: aes.ofb_crypt(value, iv),
             lambda value: aes.ofb_crypt(value, iv)),
            ("CTR", lambda value: aes.ctr_crypt(value, iv),
             lambda value: aes.ctr_crypt(value, iv)),
        ):
            ciphertext = encrypt(data)
            print("{} ciphertext = {}".format(label, ciphertext.hex()))
            check(label + " binary round trip", decrypt(ciphertext), data)
        check("ECB unpadded round trip",
              aes.ecb_decrypt(aes.ecb_encrypt(plaintext, padding=False), padding=False), plaintext)
        check("CBC unpadded round trip",
              aes.cbc_decrypt(aes.cbc_encrypt(plaintext, iv, padding=False), iv, padding=False), plaintext)
        check("ECB empty padded round trip", aes.ecb_decrypt(aes.ecb_encrypt(b"")), b"")
        check("CTR empty result", aes.ctr_crypt(b"", bytes(16)), b"")

        # NIST SP 800-38B, example 1 (empty message).
        tag = aes.cmac(b"")
        check("CMAC known-answer tag", tag, bytes.fromhex("bb1d6929e95937287fa37d129b756746"))
        check("CMAC verification", aes.cmac_verify(b"", tag), True)
        check("CMAC wrong-tag rejection", aes.cmac_verify(b"", bytes(16)), False)
        nonce = bytes.fromhex("101112131415161718191a1b")
        tag = aes.gmac(aad, nonce)
        print("GMAC tag = " + tag.hex())
        check("GMAC verification", aes.gmac_verify(aad, nonce, tag), True)
        check("GMAC changed-message rejection", aes.gmac_verify(aad + b"!", nonce, tag), False)

        nonce = bytes.fromhex("202122232425262728292a")
        ciphertext = aes.ccm_encrypt(data, nonce, aad, tag_length=12)
        print("CCM ciphertext || tag = " + ciphertext.hex())
        check("CCM binary round trip", aes.ccm_decrypt(ciphertext, nonce, aad, tag_length=12), data)
        reject_forgery("CCM", lambda value: aes.ccm_decrypt(value, nonce, aad, tag_length=12), ciphertext)
        wrapped = aes.kwp_wrap(b"\x00short key\xff")
        print("KWP wrapped key = " + wrapped.hex())
        check("KWP partial-block round trip", aes.kwp_unwrap(wrapped), b"\x00short key\xff")

    # RFC 3394 section 4.1: 128-bit KEK wrapping a 128-bit key.
    with library.aes(bytes.fromhex(vectors[0][0])) as aes:
        expected = bytes.fromhex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
        check("KW known-answer wrapped key", aes.kw_wrap(plaintext), expected)
        check("KW unwrapping", aes.kw_unwrap(expected), plaintext)
    try:
        aes.encrypt_block(plaintext)
    except ValueError:
        print("PASS closed-key use rejection")
    else:
        raise RuntimeError("closed key remained usable")
    aes.close()  # Idempotent; must not double free.

    # Exercise ciphertext stealing on a non-block-aligned storage data unit.
    xts_key = bytes(range(32))
    unit = data + b"\x00"
    ciphertext = library.xts_encrypt(xts_key, unit, bytes(16))
    print("XTS ciphertext = " + ciphertext.hex())
    check("XTS length preservation", len(ciphertext), len(unit))
    check("XTS ciphertext-stealing round trip", library.xts_decrypt(xts_key, ciphertext, bytes(16)), unit)

    # RFC 8452 Appendix C.1: empty plaintext and AAD.
    siv_key = bytes.fromhex("01000000000000000000000000000000")
    siv_nonce = bytes.fromhex("030000000000000000000000")
    ciphertext = library.gcm_siv_encrypt(siv_key, b"", siv_nonce)
    check("GCM-SIV known-answer tag", ciphertext, bytes.fromhex("dc20e2d83f25705bb49e439eca56de25"))
    check("GCM-SIV empty decryption", library.gcm_siv_decrypt(siv_key, ciphertext, siv_nonce), b"")
    reject_forgery("GCM-SIV", lambda value: library.gcm_siv_decrypt(siv_key, value, siv_nonce), ciphertext)


def main(argv):
    if len(argv) != 2:
        print("Usage: python3 {} PATH_TO_LIBRARY".format(argv[0]), file=sys.stderr)
        return 2
    try:
        run(Library(argv[1]))
    except Exception as error:
        print("FAIL: {}: {}".format(type(error).__name__, error), file=sys.stderr)
        return 1
    print("All native Python demo checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
