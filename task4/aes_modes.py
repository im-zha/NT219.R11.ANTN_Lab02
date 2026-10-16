"""Standard-library ctypes access to the AESModes C ABI.

Build a shared library with ``cmake -S . -B build -DAES_LIBRARY_TYPE=BOTH``
and ``cmake --build build``. Load its actual file explicitly, for example
``Library('/absolute/path/to/build/modes/libaes_modes.so')``; no library search,
Python cryptography, or fallback implementation is used.

Use ``with library.aes(key_bytes) as aes: ...`` to release the native key.
Every operation accepts bytes and returns bytes, except MAC verification,
which returns bool. GCM, CCM and GCM-SIV use ciphertext || tag, not tuples.
No operation generates or prefixes IVs, nonces, counters, or tweaks. GCM/CCM
nonces must never repeat under a key; GCM-SIV nonces should remain unique.
CBC/CFB IVs must be unpredictable, and OFB IVs/CTR sequences must not repeat.
ECB/CBC/CFB/OFB/CTR and XTS do not authenticate ciphertext. XTS is for storage
units, while KW/KWP wrap key material. Callers own nonce management.
"""

import ctypes
import os
import threading


__all__ = ["Library", "AESKey", "AuthenticationError"]


class AuthenticationError(Exception):
    """Native authentication or wrapped-key integrity verification failed."""


class _Key(ctypes.Structure):
    pass


class _Buffer(ctypes.Structure):
    pass


_U8P = ctypes.POINTER(ctypes.c_uint8)
_Size = ctypes.c_size_t
_KeyP = ctypes.POINTER(_Key)
_BufferP = ctypes.POINTER(_Buffer)
_BufferPP = ctypes.POINTER(_BufferP)
_IntP = ctypes.POINTER(ctypes.c_int)


def _byte_args(value):
    """Return a pointer-compatible owner and length, retaining binary contents."""
    if not isinstance(value, bytes):
        raise TypeError("cryptographic inputs must be bytes")
    if not value:
        return None, 0
    owner = (ctypes.c_uint8 * len(value)).from_buffer_copy(value)
    return owner, len(value)


def _integer(value, name):
    if not isinstance(value, int):
        raise TypeError(name + " must be an integer")
    bits = ctypes.sizeof(ctypes.c_int) * 8
    if not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        raise ValueError(name + " is outside the native int range")
    return value


def _padding(value):
    if not isinstance(value, bool):
        raise TypeError("padding must be bool")
    return int(value)


class Library:
    """Load exactly the supplied shared-library path; loader errors propagate."""

    def __init__(self, path):
        path = os.fspath(path)
        if not path:
            raise ValueError("an explicit shared-library path is required")
        path = os.path.abspath(path)
        if os.name == "nt" and hasattr(os, "add_dll_directory"):
            with os.add_dll_directory(os.fsdecode(os.path.dirname(path))):
                self._native = ctypes.CDLL(path)
        else:
            self._native = ctypes.CDLL(path)
        self._configure()

    def _configure(self):
        native = self._native
        accessors = {
            "last_error": ([], ctypes.c_char_p),
            "key_create": ([_U8P, _Size, ctypes.POINTER(_KeyP)], ctypes.c_int),
            "key_destroy": ([_KeyP], None),
            "buffer_data": ([_BufferP], _U8P),
            "buffer_size": ([_BufferP], _Size),
            "buffer_destroy": ([_BufferP], None),
        }
        for name, (arguments, result) in accessors.items():
            function = getattr(native, "aes_modes_" + name)
            function.argtypes = arguments
            function.restype = result

        keyed = [_KeyP, _U8P, _Size]
        pair = [_U8P, _Size]
        signatures = {
            "encrypt_block": keyed,
            "decrypt_block": keyed,
            "ecb_encrypt": keyed + [ctypes.c_int],
            "ecb_decrypt": keyed + [ctypes.c_int],
            "cbc_encrypt": keyed + pair + [ctypes.c_int],
            "cbc_decrypt": keyed + pair + [ctypes.c_int],
            "cfb_encrypt": keyed + pair + [ctypes.c_int],
            "cfb_decrypt": keyed + pair + [ctypes.c_int],
            "ofb_crypt": keyed + pair,
            "ctr_crypt": keyed + pair,
            "cmac": keyed,
            "gmac": keyed + pair,
            "gcm_encrypt": keyed + pair + pair,
            "gcm_decrypt": keyed + pair + pair,
            "ccm_encrypt": keyed + pair + pair + [ctypes.c_int],
            "ccm_decrypt": keyed + pair + pair + [ctypes.c_int],
            "kw_wrap": keyed,
            "kw_unwrap": keyed,
            "kwp_wrap": keyed,
            "kwp_unwrap": keyed,
            "xts_encrypt": pair + pair + pair,
            "xts_decrypt": pair + pair + pair,
            "gcm_siv_encrypt": pair + pair + pair + pair,
            "gcm_siv_decrypt": pair + pair + pair + pair,
        }
        for name, arguments in signatures.items():
            function = getattr(native, "aes_modes_" + name)
            function.argtypes = arguments + [_BufferPP]
            function.restype = ctypes.c_int
        for name, arguments in {
            "cmac_verify": keyed + pair,
            "gmac_verify": keyed + pair + pair,
        }.items():
            function = getattr(native, "aes_modes_" + name)
            function.argtypes = arguments + [_IntP]
            function.restype = ctypes.c_int

    def _check(self, status):
        if status == 0:
            return
        diagnostic = self._native.aes_modes_last_error()
        message = diagnostic.decode("utf-8", errors="replace") if diagnostic else "no native diagnostic"
        exception = {
            1: ValueError,
            2: AuthenticationError,
            3: OverflowError,
            4: OverflowError,
            5: MemoryError,
            6: RuntimeError,
        }.get(status, RuntimeError)
        raise exception("AESModes status {}: {}".format(status, message))

    def _result(self, name, *arguments):
        # The arguments tuple owns all ctypes input arrays until the call ends.
        result = _BufferP()
        try:
            function = getattr(self._native, "aes_modes_" + name)
            self._check(function(*arguments, ctypes.byref(result)))
            if not result:
                raise RuntimeError("AESModes returned a null result on success")
            size = self._native.aes_modes_buffer_size(result)
            if not size:
                return b""
            return ctypes.string_at(self._native.aes_modes_buffer_data(result), size)
        finally:
            if result:
                self._native.aes_modes_buffer_destroy(result)

    def aes(self, key):
        """Create an AES-128/192/256 key; close it or use a with statement."""
        return AESKey(self, key)

    def xts_encrypt(self, key, data, tweak):
        return self._result("xts_encrypt", *_byte_args(key), *_byte_args(data), *_byte_args(tweak))

    def xts_decrypt(self, key, data, tweak):
        return self._result("xts_decrypt", *_byte_args(key), *_byte_args(data), *_byte_args(tweak))

    def gcm_siv_encrypt(self, key, data, nonce, aad=b""):
        return self._result("gcm_siv_encrypt", *_byte_args(key), *_byte_args(data),
                            *_byte_args(nonce), *_byte_args(aad))

    def gcm_siv_decrypt(self, key, data, nonce, aad=b""):
        return self._result("gcm_siv_decrypt", *_byte_args(key), *_byte_args(data),
                            *_byte_args(nonce), *_byte_args(aad))


class AESKey:
    """Owned native AES key; methods reject a closed handle.

    The Library remains alive for the key's lifetime. A lifecycle lock prevents
    close from destroying a key while a ctypes call has released Python's GIL.
    """

    def __init__(self, library, key):
        self._library = library
        self._lock = threading.RLock()
        self._handle = _KeyP()
        try:
            library._check(library._native.aes_modes_key_create(
                *_byte_args(key), ctypes.byref(self._handle)))
            if not self._handle:
                raise RuntimeError("AESModes returned a null key on success")
        except BaseException:
            self.close()
            raise

    def _require_open(self):
        if not self._handle:
            raise ValueError("AES key is closed")

    def close(self):
        """Release the native key once; repeated close calls are harmless."""
        with self._lock:
            handle = self._handle
            self._handle = _KeyP()
            if handle:
                self._library._native.aes_modes_key_destroy(handle)

    def __enter__(self):
        with self._lock:
            self._require_open()
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            # Partially constructed objects and interpreter shutdown are safe.
            pass

    def _result(self, name, *arguments):
        with self._lock:
            self._require_open()
            return self._library._result(name, self._handle, *arguments)

    def _verify(self, name, *arguments):
        valid = ctypes.c_int()
        with self._lock:
            self._require_open()
            function = getattr(self._library._native, "aes_modes_" + name)
            self._library._check(function(self._handle, *arguments, ctypes.byref(valid)))
        return bool(valid.value)

    def encrypt_block(self, data):
        return self._result("encrypt_block", *_byte_args(data))

    def decrypt_block(self, data):
        return self._result("decrypt_block", *_byte_args(data))

    def ecb_encrypt(self, data, padding=True):
        return self._result("ecb_encrypt", *_byte_args(data), _padding(padding))

    def ecb_decrypt(self, data, padding=True):
        return self._result("ecb_decrypt", *_byte_args(data), _padding(padding))

    def cbc_encrypt(self, data, iv, padding=True):
        return self._result("cbc_encrypt", *_byte_args(data), *_byte_args(iv), _padding(padding))

    def cbc_decrypt(self, data, iv, padding=True):
        return self._result("cbc_decrypt", *_byte_args(data), *_byte_args(iv), _padding(padding))

    def cfb_encrypt(self, data, iv, segment_bits=128):
        return self._result("cfb_encrypt", *_byte_args(data), *_byte_args(iv),
                            _integer(segment_bits, "segment_bits"))

    def cfb_decrypt(self, data, iv, segment_bits=128):
        return self._result("cfb_decrypt", *_byte_args(data), *_byte_args(iv),
                            _integer(segment_bits, "segment_bits"))

    def ofb_crypt(self, data, iv):
        return self._result("ofb_crypt", *_byte_args(data), *_byte_args(iv))

    def ctr_crypt(self, data, counter):
        return self._result("ctr_crypt", *_byte_args(data), *_byte_args(counter))

    def cmac(self, data):
        return self._result("cmac", *_byte_args(data))

    def cmac_verify(self, data, tag):
        return self._verify("cmac_verify", *_byte_args(data), *_byte_args(tag))

    def gmac(self, data, nonce):
        return self._result("gmac", *_byte_args(data), *_byte_args(nonce))

    def gmac_verify(self, data, nonce, tag):
        return self._verify("gmac_verify", *_byte_args(data), *_byte_args(nonce), *_byte_args(tag))

    def gcm_encrypt(self, data, nonce, aad=b""):
        return self._result("gcm_encrypt", *_byte_args(data), *_byte_args(nonce), *_byte_args(aad))

    def gcm_decrypt(self, data, nonce, aad=b""):
        return self._result("gcm_decrypt", *_byte_args(data), *_byte_args(nonce), *_byte_args(aad))

    def ccm_encrypt(self, data, nonce, aad=b"", tag_length=16):
        return self._result("ccm_encrypt", *_byte_args(data), *_byte_args(nonce),
                            *_byte_args(aad), _integer(tag_length, "tag_length"))

    def ccm_decrypt(self, data, nonce, aad=b"", tag_length=16):
        return self._result("ccm_decrypt", *_byte_args(data), *_byte_args(nonce),
                            *_byte_args(aad), _integer(tag_length, "tag_length"))

    def kw_wrap(self, data):
        return self._result("kw_wrap", *_byte_args(data))

    def kw_unwrap(self, data):
        return self._result("kw_unwrap", *_byte_args(data))

    def kwp_wrap(self, data):
        return self._result("kwp_wrap", *_byte_args(data))

    def kwp_unwrap(self, data):
        return self._result("kwp_unwrap", *_byte_args(data))
