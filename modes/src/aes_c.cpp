#include "aes_c.h"
#include "aes.hpp"
#include "common.hpp"
#include "sp800_38a.hpp"
#include "sp800_38b.hpp"
#include "sp800_38c.hpp"
#include "sp800_38d.hpp"
#include "sp800_38e.hpp"
#include "sp800_38f.hpp"
#include "rfc8452_gcm_siv.hpp"

#include <algorithm>
#include <exception>
#include <new>
#include <stdexcept>
#include <utility>

using namespace std;

struct aes_modes_key {
    explicit aes_modes_key(const Bytes& key) : schedule(key) {}
    const AES schedule;
};

struct aes_modes_buffer {
    explicit aes_modes_buffer(Bytes&& result) noexcept : bytes(move(result)) {}
    const Bytes bytes;
};

namespace {

thread_local char error_text[512] = {};

void set_error(const char* message) noexcept {
    size_t i = 0;
    if (message != nullptr) {
        while (i + 1 < sizeof(error_text) && message[i] != '\0') {
            error_text[i] = message[i];
            ++i;
        }
    }
    error_text[i] = '\0';
}

// Only the authenticated decrypt/unwrap APIs use runtime_error to report
// integrity failures. Other runtime errors remain internal errors.
template <class Function>
int boundary(Function&& function, bool authentication = false) noexcept {
    error_text[0] = '\0';
    try {
        function();
        return AES_MODES_OK;
    } catch (const invalid_argument& error) {
        set_error(error.what());
        return AES_MODES_INVALID_ARGUMENT;
    } catch (const length_error& error) {
        set_error(error.what());
        return AES_MODES_LENGTH_ERROR;
    } catch (const overflow_error& error) {
        set_error(error.what());
        return AES_MODES_COUNTER_OVERFLOW;
    } catch (const bad_alloc& error) {
        set_error(error.what());
        return AES_MODES_OUT_OF_MEMORY;
    } catch (const runtime_error& error) {
        set_error(error.what());
        return authentication ? AES_MODES_AUTH_FAILED : AES_MODES_INTERNAL_ERROR;
    } catch (const exception& error) {
        set_error(error.what());
        return AES_MODES_INTERNAL_ERROR;
    } catch (...) {
        set_error("Unknown native exception.");
        return AES_MODES_INTERNAL_ERROR;
    }
}

template <class Function>
int buffer_result(aes_modes_buffer** out, Function&& function,
                  bool authentication = false) noexcept {
    return boundary([&] {
        if (out == nullptr) throw invalid_argument("Output buffer pointer must not be NULL.");
        *out = nullptr;
        *out = new aes_modes_buffer(function());
    }, authentication);
}

template <class Function>
int verification_result(int* valid, Function&& function) noexcept {
    return boundary([&] {
        if (valid == nullptr) throw invalid_argument("Verification output pointer must not be NULL.");
        *valid = 0;
        *valid = function() ? 1 : 0;
    });
}

void check_input(const uint8_t* data, size_t size) {
    if (data == nullptr && size != 0) {
        throw invalid_argument("Input pointer must not be NULL for a nonzero length.");
    }
}

Bytes copy_bytes(const uint8_t* data, size_t size) {
    check_input(data, size);
    if (size == 0) return {};
    // Check before forming the end pointer, including for unrepresentable lengths.
    if (size > Bytes{}.max_size()) throw length_error("Input is too large.");
    return Bytes(data, data + size);
}

Bytes verification_tag(const uint8_t* tag, size_t size) {
    check_input(tag, size);
    // Native verification treats every non-16-byte tag as a mismatch. Avoid
    // copying an arbitrarily large malformed tag just to obtain that result.
    if (size != AES::BLOCK_SIZE) return {};
    return copy_bytes(tag, size);
}

const AES& checked_key(const aes_modes_key* key) {
    if (key == nullptr) throw invalid_argument("Key handle must not be NULL.");
    return key->schedule;
}

bool checked_padding(int padding) {
    if (padding != 0 && padding != 1) {
        throw invalid_argument("Padding must be 0 or 1.");
    }
    return padding != 0;
}

Block input_block(const uint8_t* input, size_t size) {
    check_input(input, size);
    if (size != AES::BLOCK_SIZE) {
        throw invalid_argument("An AES block must contain exactly 16 bytes.");
    }
    Block block;
    copy_n(input, block.size(), block.begin());
    return block;
}

} // namespace

extern "C" {

const char* aes_modes_last_error(void) noexcept {
    return error_text;
}

int aes_modes_key_create(const uint8_t* key, size_t key_size,
                         aes_modes_key** out) noexcept {
    return boundary([&] {
        if (out == nullptr) throw invalid_argument("Output key pointer must not be NULL.");
        *out = nullptr;
        check_input(key, key_size);
        if (key_size != 16 && key_size != 24 && key_size != 32) {
            throw invalid_argument("AES keys must contain 16, 24 or 32 bytes.");
        }
        *out = new aes_modes_key(copy_bytes(key, key_size));
    });
}

void aes_modes_key_destroy(aes_modes_key* key) noexcept {
    delete key;
}

const uint8_t* aes_modes_buffer_data(const aes_modes_buffer* buffer) noexcept {
    return buffer == nullptr ? nullptr : buffer->bytes.data();
}

size_t aes_modes_buffer_size(const aes_modes_buffer* buffer) noexcept {
    return buffer == nullptr ? 0 : buffer->bytes.size();
}

void aes_modes_buffer_destroy(aes_modes_buffer* buffer) noexcept {
    delete buffer;
}

int aes_modes_encrypt_block(const aes_modes_key* key, const uint8_t* input,
                            size_t size, aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        const Block result = checked_key(key).encrypt(input_block(input, size));
        return Bytes(result.begin(), result.end());
    });
}

int aes_modes_decrypt_block(const aes_modes_key* key, const uint8_t* input,
                            size_t size, aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        const Block result = checked_key(key).decrypt(input_block(input, size));
        return Bytes(result.begin(), result.end());
    });
}

int aes_modes_ecb_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          int padding, aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::ecb_encrypt(checked_key(key), copy_bytes(input, size), checked_padding(padding));
    });
}

int aes_modes_ecb_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          int padding, aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::ecb_decrypt(checked_key(key), copy_bytes(input, size), checked_padding(padding));
    });
}

int aes_modes_cbc_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* iv, size_t iv_size, int padding,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::cbc_encrypt(checked_key(key), copy_bytes(input, size),
                                copy_bytes(iv, iv_size), checked_padding(padding));
    });
}

int aes_modes_cbc_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* iv, size_t iv_size, int padding,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::cbc_decrypt(checked_key(key), copy_bytes(input, size),
                                copy_bytes(iv, iv_size), checked_padding(padding));
    });
}

int aes_modes_cfb_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* iv, size_t iv_size, int segment_bits,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::cfb_encrypt(checked_key(key), copy_bytes(input, size),
                                copy_bytes(iv, iv_size), segment_bits);
    });
}

int aes_modes_cfb_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* iv, size_t iv_size, int segment_bits,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::cfb_decrypt(checked_key(key), copy_bytes(input, size),
                                copy_bytes(iv, iv_size), segment_bits);
    });
}

int aes_modes_ofb_crypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                        const uint8_t* iv, size_t iv_size,
                        aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::ofb_crypt(checked_key(key), copy_bytes(input, size), copy_bytes(iv, iv_size));
    });
}

int aes_modes_ctr_crypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                        const uint8_t* counter, size_t counter_size,
                        aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::ctr_crypt(checked_key(key), copy_bytes(input, size),
                              copy_bytes(counter, counter_size));
    });
}

int aes_modes_cmac(const aes_modes_key* key, const uint8_t* input, size_t size,
                   aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::cmac(checked_key(key), copy_bytes(input, size));
    });
}

int aes_modes_cmac_verify(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* tag, size_t tag_size,
                          int* valid) noexcept {
    return verification_result(valid, [&] {
        return lab::cmac_verify(checked_key(key), copy_bytes(input, size),
                                verification_tag(tag, tag_size));
    });
}

int aes_modes_gmac(const aes_modes_key* key, const uint8_t* input, size_t size,
                   const uint8_t* nonce, size_t nonce_size,
                   aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::gmac(checked_key(key), copy_bytes(input, size), copy_bytes(nonce, nonce_size));
    });
}

int aes_modes_gmac_verify(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* tag, size_t tag_size,
                          int* valid) noexcept {
    return verification_result(valid, [&] {
        return lab::gmac_verify(checked_key(key), copy_bytes(input, size),
                                verification_tag(tag, tag_size), copy_bytes(nonce, nonce_size));
    });
}

int aes_modes_gcm_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* aad, size_t aad_size,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::gcm_encrypt(checked_key(key), copy_bytes(input, size),
                                copy_bytes(nonce, nonce_size), copy_bytes(aad, aad_size));
    });
}

int aes_modes_gcm_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* aad, size_t aad_size,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::gcm_decrypt(checked_key(key), copy_bytes(input, size),
                                copy_bytes(nonce, nonce_size), copy_bytes(aad, aad_size));
    }, true);
}

int aes_modes_ccm_encrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* aad, size_t aad_size, int tag_size,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::ccm_encrypt(checked_key(key), copy_bytes(input, size),
                                copy_bytes(nonce, nonce_size), copy_bytes(aad, aad_size), tag_size);
    });
}

int aes_modes_ccm_decrypt(const aes_modes_key* key, const uint8_t* input, size_t size,
                          const uint8_t* nonce, size_t nonce_size,
                          const uint8_t* aad, size_t aad_size, int tag_size,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::ccm_decrypt(checked_key(key), copy_bytes(input, size),
                                copy_bytes(nonce, nonce_size), copy_bytes(aad, aad_size), tag_size);
    }, true);
}

int aes_modes_kw_wrap(const aes_modes_key* key, const uint8_t* input, size_t size,
                      aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::kw_wrap(checked_key(key), copy_bytes(input, size));
    });
}

int aes_modes_kw_unwrap(const aes_modes_key* key, const uint8_t* input, size_t size,
                        aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::kw_unwrap(checked_key(key), copy_bytes(input, size));
    }, true);
}

int aes_modes_kwp_wrap(const aes_modes_key* key, const uint8_t* input, size_t size,
                       aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::kwp_wrap(checked_key(key), copy_bytes(input, size));
    });
}

int aes_modes_kwp_unwrap(const aes_modes_key* key, const uint8_t* input, size_t size,
                         aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::kwp_unwrap(checked_key(key), copy_bytes(input, size));
    }, true);
}

int aes_modes_xts_encrypt(const uint8_t* key, size_t key_size,
                          const uint8_t* input, size_t size,
                          const uint8_t* tweak, size_t tweak_size,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::xts_encrypt(copy_bytes(key, key_size), copy_bytes(input, size),
                                copy_bytes(tweak, tweak_size));
    });
}

int aes_modes_xts_decrypt(const uint8_t* key, size_t key_size,
                          const uint8_t* input, size_t size,
                          const uint8_t* tweak, size_t tweak_size,
                          aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::xts_decrypt(copy_bytes(key, key_size), copy_bytes(input, size),
                                copy_bytes(tweak, tweak_size));
    });
}

int aes_modes_gcm_siv_encrypt(const uint8_t* key, size_t key_size,
                              const uint8_t* input, size_t size,
                              const uint8_t* nonce, size_t nonce_size,
                              const uint8_t* aad, size_t aad_size,
                              aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::gcm_siv_encrypt(copy_bytes(key, key_size), copy_bytes(input, size),
                                    copy_bytes(nonce, nonce_size), copy_bytes(aad, aad_size));
    });
}

int aes_modes_gcm_siv_decrypt(const uint8_t* key, size_t key_size,
                              const uint8_t* input, size_t size,
                              const uint8_t* nonce, size_t nonce_size,
                              const uint8_t* aad, size_t aad_size,
                              aes_modes_buffer** out) noexcept {
    return buffer_result(out, [&] {
        return lab::gcm_siv_decrypt(copy_bytes(key, key_size), copy_bytes(input, size),
                                    copy_bytes(nonce, nonce_size), copy_bytes(aad, aad_size));
    }, true);
}

} // extern "C"
