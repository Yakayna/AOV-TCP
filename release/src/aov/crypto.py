"""TSF crypto primitives for Lien Quan Mobile (AOV VN) 1.64.x.

Every value here was verified against the real client library
``libgcloud.so`` (md5 2d023cdcdd0b52786b122fc65893568f) and against
live captures of the unmodified game:

* the AES-128 key is the **16 raw bytes** carried by the server's
  ``0x1002`` reply (the library expands the round keys itself at
  ``0x27d3ec``);
* the per-frame IV struct is ``HEAD || u16be(tail)`` encrypted with
  AES-ECB under that key;
* a frame body is ``iv(16) || AES-CBC(key, iv, plaintext)``.

The 16-bit ``tail`` is **per account** and is validated by the server:
a wrong tail makes ``0x2001`` fail immediately with ``0x5002``.
Use ``brute_tail.py`` to recover it for an account.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Constant prefix of the IV struct.  Recovered by decrypting the IV of a
# real 0x2001 frame with the session key; it is identical for every
# account and every session of build 1.64.1.11.
HEAD = bytes.fromhex('fffe02073534353008360b0b2547')

BLOCK = 16


def ecb_enc(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def ecb_dec(key: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def cbc_enc(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def cbc_dec(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def iv_for(key: bytes, tail: int) -> bytes:
    """Build the 16-byte IV for a session tail."""
    return ecb_enc(key, HEAD + struct.pack('>H', tail & 0xFFFF))


def seal(key: bytes, tail: int, plaintext: bytes) -> bytes:
    """Return ``iv || ciphertext`` ready to be used as a frame body.

    The plaintext is zero-padded to the AES block boundary; the receiver
    strips the padding using the ``padlen``/``tsf4g`` trailer inside the
    payload.
    """
    iv = iv_for(key, tail)
    pad = (-len(plaintext)) % BLOCK
    return iv + cbc_enc(key, iv, plaintext + b'\x00' * pad)


def unseal(key: bytes, body: bytes) -> bytes:
    """Decrypt a frame body (``iv || ciphertext``)."""
    if len(body) < 32:
        raise ValueError('body too short')
    iv, ct = body[:BLOCK], body[BLOCK:]
    return cbc_dec(key, iv, ct)


def pad(plaintext: bytes, tag: bytes = b'tsf4g', padlen: int = 0x07) -> bytes:
    """Pad a TSF payload to a 16-byte boundary.

    Layout used by the client for login frames::

        [payload] [filler] [padlen] [tag]     (0x2001)
        [payload] [filler] [tag] [padlen]     (most other frames)

    ``padlen`` tells the receiver how many filler bytes to drop, so the
    filler itself is irrelevant (the client fills it with ``rand()``).
    """
    target = (len(plaintext) + 6 + BLOCK - 1) // BLOCK * BLOCK
    fill = target - len(plaintext) - 2 - len(tag)
    return plaintext + bytes(fill) + bytes([padlen]) + tag
