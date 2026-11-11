"""TSF framing: ``33 66`` header + encrypted body, over a plain TCP stream.

Wire layout (little/big endianness is *mixed* on purpose, this is what the
client library emits)::

    off  size  field
    0    2     magic 33 66
    2    2     version/flags (00 08)
    4    2     version/flags (00 08)
    6    2     command, big endian
    8    4     counter high (big endian, usually 0)
    12   4     counter low  (little endian)  == transport seq
    16   2     header length, little endian
    18   1     flags
    19   2     body length, big endian
    21   n     body: iv(16) || AES-CBC ciphertext
"""
from __future__ import annotations

import struct

MAGIC = b'\x33\x66'


def parse(blob: bytes) -> list[bytes]:
    """Split a byte stream into complete frames (best effort)."""
    out = []
    i = 0
    while i + 21 <= len(blob):
        if blob[i:i + 2] == MAGIC:
            hl = struct.unpack_from('<H', blob, i + 16)[0]
            bl = struct.unpack_from('>H', blob, i + 19)[0]
            if 21 <= hl <= 4096 and i + hl + bl <= len(blob):
                out.append(blob[i:i + hl + bl])
                i += hl + bl
                continue
        i += 1
    return out


def cmd(frame: bytes) -> int:
    return int.from_bytes(frame[6:8], 'big')


def seq(frame: bytes) -> int:
    return struct.unpack_from('<I', frame, 12)[0]


def body(frame: bytes) -> bytes:
    hl = struct.unpack_from('<H', frame, 16)[0]
    return frame[hl:]


def build(header: bytes, seqno: int, body_bytes: bytes) -> bytes:
    """Stamp a header template with a transport sequence number and length."""
    h = bytearray(header)
    struct.pack_into('<I', h, 12, seqno & 0xFFFFFFFF)
    struct.pack_into('>H', h, 19, len(body_bytes))
    return bytes(h) + body_bytes
