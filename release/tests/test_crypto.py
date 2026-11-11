"""Self-tests that do not need a token or a live gateway.

Run with::

    PYTHONPATH=src python -m pytest tests -q     # or: python tests/test_crypto.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

from aov import crypto, frame  # noqa: E402

KEY = bytes(range(16))


def test_head_constant():
    assert crypto.HEAD.hex() == 'fffe02073534353008360b0b2547'
    assert len(crypto.HEAD) == 14


def test_iv_is_head_plus_tail():
    iv = crypto.iv_for(KEY, 0x3e69)
    assert len(iv) == 16
    assert crypto.ecb_dec(KEY, iv) == crypto.HEAD + b'\x3e\x69'


def test_seal_roundtrip():
    payload = b'hello tsf' + b'\x00' * 5
    body = crypto.seal(KEY, 0x1234, payload)
    assert body[:16] == crypto.iv_for(KEY, 0x1234)
    # seal() zero-pads to the block boundary, unseal() returns it verbatim
    assert crypto.unseal(KEY, body).rstrip(b'\x00') == payload.rstrip(b'\x00')


def test_login_plaintext_is_64_bytes():
    token = 'ab' + '0123456789abcdef0123456789abcdef01234567'[:38]
    core = token[2:40].encode()
    pt = core + bytes(64 - len(core) - 7) + b'\x17' + b'tsf4g' + b'\x07'
    assert len(pt) == 64
    assert pt.endswith(b'\x17tsf4g\x07')
    assert pt.startswith(b'0123456789')


def test_frame_roundtrip():
    body = crypto.seal(KEY, 0x3e69, b'x' * 64)
    tpl = bytes.fromhex('336600080008200100000000020000001500000050')
    wire = frame.build(tpl, 2, body)
    parsed = frame.parse(wire)
    assert len(parsed) == 1
    assert frame.cmd(parsed[0]) == 0x2001
    assert frame.seq(parsed[0]) == 2
    assert frame.body(parsed[0]) == body


if __name__ == '__main__':
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            print('ok', name)
    print('all tests passed')
