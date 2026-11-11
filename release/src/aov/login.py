"""Clientless login handshake against the AOV gateway (TCP 6629/6630).

What this module does, verified against the unmodified game and against
``libgcloud.so``:

1. connect to the gateway;
2. send ``0x1001`` (login SYN, carries the MSDK openid) -> the server
   answers ``0x1002`` which carries the **16-byte AES key** at [23:39];
3. send ``0x2001`` (login with the 40-hex game token) sealed with
   ``iv = ECB(key, HEAD || tail)`` -> the server answers ``0x2002``
   (account blob), ``0x6002`` (28-byte session blob) and the first
   ``0x4013`` frames.  That is a **successful account login**.

Known limitation (see docs/findings.md): the gateway never starts the
lobby stream for a PC-side client even though the login is accepted,
while the real app on the same account/IP does get it.  The remaining
gate is server-side session registration; the framing below is
byte-identical to the app's.
"""
from __future__ import annotations

import json
import os
import random
import socket
import struct
import sys
import time

from . import crypto, frame
from .raw1001 import build as build_1001

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, '..', '..', 'data')

CMD_KEY = 0x1002
CMD_LOGIN = 0x2001
CMD_LOGIN_OK = 0x2002
CMD_SESSION = 0x6002
CMD_REPORT = 0x4013


def load_template() -> dict:
    with open(os.path.join(DATA, 'login_template.json'), encoding='utf-8') as fh:
        return json.load(fh)


def read_until(sock: socket.socket, want: set[int], deadline: float) -> dict[int, bytes]:
    """Read frames until every command in *want* was seen or time runs out."""
    seen: dict[int, bytes] = {}
    buf = b''
    while time.time() < deadline and not want.issubset(seen):
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk
        for fr in frame.parse(buf):
            c = frame.cmd(fr)
            seen.setdefault(c, fr)
        # keep only the trailing partial frame
        if len(buf) > 65536:
            buf = buf[-65536:]
    return seen


def login(token: str, openid: str, tail: int, host: str, port: int,
          timeout: float = 8.0, verbose: bool = True) -> dict:
    """Run the handshake.  Returns a dict describing what the server answered."""
    tpl = load_template()
    result = {'key': None, 'commands': [], 'lobby_frames': 0, 'ok': False}

    sock = socket.create_connection((host, port), timeout=6)
    sock.settimeout(0.5)
    try:
        # --- 0x1001: login SYN, the server replies with the AES key -------
        syn = bytearray(build_1001(bytes.fromhex(tpl['raw1001']), openid))
        syn[32] = 0x02
        sock.sendall(bytes(syn))

        deadline = time.time() + timeout
        got = read_until(sock, {CMD_KEY}, deadline)
        if CMD_KEY not in got:
            return result
        key = got[CMD_KEY][23:39]
        result['key'] = key

        # --- 0x2001: login with the game token ----------------------------
        # plaintext is exactly 64 bytes, byte-identical to the real app:
        #   "<38 hex chars>" + 19 zero bytes + 0x17 + "tsf4g" + 0x07
        core = token[2:40].encode()
        pt = core + bytes(64 - len(core) - 7) + b'\x17' + b'tsf4g' + b'\x07'
        assert len(pt) == 64, len(pt)
        body = crypto.seal(key, tail, pt)
        sock.sendall(frame.build(bytes.fromhex(tpl['hdr_2001']), 2, body))

        deadline = time.time() + timeout
        got = read_until(sock, {CMD_LOGIN_OK, CMD_SESSION}, deadline)
        result['commands'] = sorted(got)
        result['ok'] = CMD_LOGIN_OK in got

        if verbose:
            for c, fr in sorted(got.items()):
                print('[recv] cmd=0x%04x len=%d' % (c, len(fr)))

        # --- optional: device report (0x4013), then watch for the lobby ---
        report = got.get(CMD_REPORT)
        if report is not None:
            sock.sendall(report)
            if verbose:
                print('[send] 0x4013 report (%d bytes)' % len(report))
        deadline = time.time() + 12
        lobby = 0
        buf = b''
        while time.time() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            lobby += len(frame.parse(buf))
            buf = b''
        result['lobby_frames'] = lobby
    finally:
        sock.close()
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description='AOV clientless login (gateway handshake)')
    ap.add_argument('--token-json', required=True,
                    help="itop build-login output (contains 'token' and 'openid')")
    ap.add_argument('--tail', required=True, help='16-bit session tail, e.g. 3e69')
    ap.add_argument('--gw', default='148.222.90.149:6630', help='gateway host:port')
    ap.add_argument('--timeout', type=float, default=8.0)
    args = ap.parse_args(argv)

    with open(args.token_json, encoding='utf-8') as fh:
        blob = json.load(fh)
    cred = blob.get('response', blob)
    token = cred['token']
    openid = str(cred['openid'])
    host, _, port = args.gw.partition(':')

    res = login(token, openid, int(args.tail, 16), host, int(port or 6630),
                timeout=args.timeout)
    print('[key] %r' % (res['key'],))
    print('[login] ok=%s commands=%s lobby_frames=%d'
          % (res['ok'], ['0x%04x' % c for c in res['commands']], res['lobby_frames']))
    return 0 if res['ok'] else 2


if __name__ == '__main__':
    sys.exit(main())
