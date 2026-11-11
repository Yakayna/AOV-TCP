"""Recover the 16-bit per-account ``tail`` used to build the session IV.

The server validates ``iv = AES-ECB(key, HEAD || tail)``: a wrong tail
makes ``0x2001`` fail at once (``0x5002``), the right one yields
``0x2002``.  So the tail can be brute-forced in parallel: every worker
keeps its own socket, asks for a fresh key (``0x1001``) and tries a slice
of the 65536 candidates.

Usage::

    python -m aov.brute_tail --token-json token.json --gw HOST:PORT --threads 32
"""
from __future__ import annotations

import json
import random
import socket
import struct
import sys
import threading
import time

from . import crypto, frame
from .raw1001 import build as build_1001

_tpl = None


def _template() -> dict:
    global _tpl
    if _tpl is None:
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', '..', 'data', 'login_template.json')
        with open(path, encoding='utf-8') as fh:
            _tpl = json.load(fh)
    return _tpl


def _attempt(host: str, port: int, token: str, openid: str, tail: int,
             timeout: float = 4.0) -> bool:
    tpl = _template()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False
    sock.settimeout(0.35)
    try:
        syn = bytearray(build_1001(bytes.fromhex(tpl['raw1001']), openid))
        syn[32] = 0x02
        sock.sendall(bytes(syn))
        buf = b''
        key = None
        deadline = time.time() + timeout
        while time.time() < deadline and key is None:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return False
            buf += chunk
            for fr in frame.parse(buf):
                if frame.cmd(fr) == 0x1002 and len(fr) >= 39:
                    key = fr[23:39]
        if key is None:
            return False

        core = token[2:40].encode()
        pt = core + bytes(64 - len(core) - 7) + b'\x17' + b'tsf4g' + b'\x07'
        body = crypto.seal(key, tail, pt)
        sock.sendall(frame.build(bytes.fromhex(tpl['hdr_2001']), 2, body))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return False
            for fr in frame.parse(chunk):
                if frame.cmd(fr) == 0x2002:
                    return True
        return False
    except OSError:
        return False
    finally:
        sock.close()


def brute(token: str, openid: str, host: str, port: int, threads: int = 32,
          timeout: float = 4.0) -> int | None:
    found: list[int] = []
    lock = threading.Lock()

    def worker(lo: int, hi: int) -> None:
        for tail in range(lo, hi):
            if found:
                return
            if _attempt(host, port, token, openid, tail, timeout):
                with lock:
                    if not found:
                        found.append(tail)
                        print('[+] tail = %04x' % tail, flush=True)
                return

    step = (0x10000 + threads - 1) // threads
    jobs = [threading.Thread(target=worker, args=(i * step, min((i + 1) * step, 0x10000)),
                             daemon=True) for i in range(threads)]
    for j in jobs:
        j.start()
    for j in jobs:
        j.join()
    return found[0] if found else None


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description='brute-force the per-account 16-bit tail')
    ap.add_argument('--token-json', required=True)
    ap.add_argument('--gw', default='148.222.90.149:6630')
    ap.add_argument('--threads', type=int, default=32)
    args = ap.parse_args(argv)

    with open(args.token_json, encoding='utf-8') as fh:
        blob = json.load(fh)
    cred = blob.get('response', blob)
    token = cred['token']
    openid = str(cred['openid'])
    host, _, port = args.gw.partition(':')

    tail = brute(token, openid, host, int(port or 6630), args.threads)
    if tail is None:
        print('[-] not found')
        return 2
    print('tail=%04x' % tail)
    return 0


if __name__ == '__main__':
    sys.exit(main())
