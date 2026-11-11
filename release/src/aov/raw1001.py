# -*- coding: utf-8 -*-
"""Build the 0x1001 login frame for an arbitrary MSDK openid.

The 0x1001 header carries the openid as a length-prefixed string::

    ... 00 00 00 11 <16/17-digit openid> 00 ...

Newer Garena accounts have a 17-digit openid, so the length prefix and the
header length must be rebuilt instead of patching a fixed 16-byte slot.
An off-by-one here silently corrupts the frame and every login attempt is
rejected (the tail brute-force then never sees 0x2002).
"""
import re
import struct

_FIELD = re.compile(rb"\x00\x00\x00[\x11\x12][0-9]{16,17}\x00")


def build(raw, openid):
    b = bytes(raw)
    m = _FIELD.search(b)
    if not m:
        raise RuntimeError('openid field not found in 0x1001 template')
    seg = struct.pack('>I', len(openid) + 1) + str(openid).encode() + b'\x00'
    out = bytearray(b[:m.start()] + seg + b[m.end():])
    struct.pack_into('<H', out, 16, len(out))  # head_len == total length
    return bytes(out)
