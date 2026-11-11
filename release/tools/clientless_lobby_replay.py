# -*- coding: utf-8 -*-
"""CLIENTLESS LOBBY REPLAY -- create a real world-session without the game client.

Method (verified 2026-10-23):
  1. Capture ONE genuine app first-login session (after server-side session expiry)
     with tcpdump on ports 6670/6629/6630 and save the client-side frame sequence
     as a template (tools/save_firstlogin_template.py -> captures/firstlogin_frames_template.json).
  2. For any target account: mint MSDK game token clientlessly (Garena login -> itop
     app-like login -> brute 16-bit auth tail), patch token/openid identifiers inside
     the template frames, then replay the frames interleaved with the server pushes
     against candidate gateways.  One gateway accepts and pushes the full lobby data
     (0x4013, CDNSharePicPath / INVALID_KEY / aovcloud ...).  The session then persists
     server-side (later f0-only connections get lobby data).

Usage:
  python tools/clientless_lobby_replay.py --token-json captures/msdk_token.json
  python tools/clientless_lobby_replay.py --token-json captures/msdk_token.json --gateways 148.222.90.36:6629
"""
import argparse, json, os, socket, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lq_decrypt
import raw1001
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEAD = bytes.fromhex("fffe02073534353008360b0b2547")
TEMPLATE = os.path.join(ROOT, "captures", "firstlogin_frames_template.json")
FRAMESET = os.path.join(ROOT, "captures", "connect_6670_frameset.json")
TAILS = os.path.join(ROOT, "captures", "token_tails.json")
EVIDENCE = os.path.join(ROOT, "captures", "lobby_session_evidence.json")
DEFAULT_GATEWAYS = [
    ("148.222.90.36", 6629), ("148.222.90.43", 6630), ("148.222.90.181", 6629),
    ("148.222.90.120", 6630), ("148.222.90.69", 6630), ("148.222.90.213", 6629),
    ("148.222.90.58", 6630), ("148.222.90.165", 6629), ("148.222.90.197", 6629),
    ("148.222.90.87", 6630),
]


def ecb(k, d):
    c = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    return c.update(d) + c.finalize()


def enc(k, iv, d):
    return lq_decrypt.aes128_cbc_encrypt(k, iv, d)


def dec(k, iv, d):
    return lq_decrypt.aes128_cbc_decrypt(k, iv, d)


def parse(buf):
    out = []; i = 0
    while i + 21 <= len(buf):
        if buf[i] == 0x33 and buf[i + 1] == 0x66:
            hl = struct.unpack_from("<H", buf, i + 16)[0]
            bl = struct.unpack_from(">H", buf, i + 19)[0]
            if 21 <= hl <= 8192 and bl <= 65535 and i + hl + bl <= len(buf):
                out.append({"hl": hl, "bl": bl, "cmd": int.from_bytes(buf[i+6:i+8], "big"),
                            "seq": struct.unpack_from("<I", buf, i+12)[0], "raw": buf[i:i+hl+bl]})
                i += hl + bl; continue
        i += 1
    return out


def log(msg):
    print(msg, flush=True)


def load_target(args):
    tok = json.load(open(args.token_json, encoding="utf-8"))["response"]
    token = tok["token"]; openid = str(tok.get("openid"))
    tails = json.load(open(args.tails, encoding="utf-8"))
    if token not in tails:
        raise SystemExit("tail for token %s not cached; run tools/brute_tail.py first" % token[:12])
    tail = int(tails[token], 16)
    return token, openid, tail


def patch_template(tpl, token, openid, openid_hex=""):
    """Patch captured identifiers with target account data (same length required)."""
    old = tpl.get("old_identifiers", {})
    repl = {
        old.get("token", ""): token,
        old.get("openid", ""): openid,
        old.get("openid_hex", ""): (openid_hex or args_openid_hex(openid)),
    }
    frames = []
    for fr in tpl["client_frames"]:
        pt = bytes.fromhex(fr["pt"])
        for a, b in repl.items():
            if a and b and len(a) == len(b):
                pt = pt.replace(a.encode(), b.encode())
        frames.append({"seq": fr["seq"], "hdr": fr["hdr"], "struct": fr["struct"],
                       "pt": pt.hex(), "needS": fr["needS"]})
    return frames


# openid in report2 is the 32-hex Garena open_id, not the 16-digit game openid.
# We only know the game openid from the token file; the 32-hex open_id comes from
# captures/garena_token.json ("open_id").  If absent we keep the captured value.
def args_openid_hex(openid):
    try:
        g = json.load(open(os.path.join(ROOT, "captures", "garena_token.json"), encoding="utf-8"))
        oid = g.get("open_id") or (g.get("response") or {}).get("open_id")
        if oid and len(str(oid)) == 32:
            return str(oid)
    except Exception:
        pass
    return ""


def run_gateway(ip, port, token, tail, frames, auth_header, raw1001, timeout=8.0):
    try:
        s = socket.create_connection((ip, port), timeout=5)
    except Exception as e:
        return {"ip": ip, "port": port, "error": "connect: %s" % e}
    try:
        s.sendall(raw1001)
        time.sleep(0.15)
        buf = b""
        try:
            while True:
                buf += s.recv(65536)
        except Exception:
            pass
        key = None
        for f in parse(buf):
            if f["cmd"] == 0x1002 and len(f["raw"]) >= 39:
                key = f["raw"][23:39]
        if not key:
            return {"ip": ip, "port": port, "error": "no 0x1002"}
        core = token[2:40]
        iv = ecb(key, HEAD + struct.pack(">H", tail))
        pt = core.encode() + b"\x00" * (64 - len(core) - 7) + b"\x17" + b"tsf4g" + b"\x07"
        body = iv + enc(key, iv, pt)
        h = bytearray(bytes.fromhex(auth_header))
        struct.pack_into(">H", h, 19, len(body))
        s.sendall(bytes(h) + body)
        time.sleep(0.1)
        buf2 = b""
        t_end = time.time() + 2.0
        while time.time() < t_end and len(buf2) < 200000:
            try:
                ch = s.recv(65536)
            except Exception:
                break
            if not ch:
                break
            buf2 += ch
        fr = parse(buf2)
        if not any(x["cmd"] == 0x2002 for x in fr):
            return {"ip": ip, "port": port, "error": "auth failed"}
        s.setblocking(False)
        got = 0; ci = 0; out_frames = []; t0 = time.time(); pending = b""
        while time.time() - t0 < timeout and ci < len(frames):
            try:
                ch = s.recv(65536)
                if not ch:
                    break
                pending += ch
            except BlockingIOError:
                pass
            except Exception:
                break
            frs = parse(pending)
            if frs:
                used = sum(x["hl"] + x["bl"] for x in frs)
                pending = pending[used:]
                got += len(frs)
                out_frames += frs
            while ci < len(frames) and frames[ci]["needS"] <= got:
                e = frames[ci]; ci += 1
                iv = ecb(key, bytes.fromhex(e["struct"]))
                p = bytes.fromhex(e["pt"])
                b2 = iv + enc(key, iv, p)
                hh = bytearray(bytes.fromhex(e["hdr"]))
                struct.pack_into(">H", hh, 19, len(b2))
                struct.pack_into("<I", hh, 12, e["seq"])
                try:
                    s.sendall(bytes(hh) + b2)
                except Exception:
                    break
                time.sleep(0.005)
            time.sleep(0.004)
        big = 0; hits = set(); samples = []
        for x in out_frames:
            if x["cmd"] == 0x5002:
                pass
            if x["cmd"] == 0x4013:
                bb = x["raw"][x["hl"]:]
                try:
                    p3 = dec(key, bb[:16], bb[16:])
                except Exception:
                    continue
                if len(p3) > 1000:
                    big += 1
                    if len(samples) < 3:
                        samples.append(p3[:80].decode("utf-8", "ignore"))
                txt = p3.decode("utf-8", "ignore")
                for kw in ("CDNSharePicPath", "INVALID_KEY", "aovcloud"):
                    if kw in txt:
                        hits.add(kw)
        sstops = [x["raw"][x["hl"]:].hex(" ") for x in out_frames if x["cmd"] == 0x5002]
        return {"ip": ip, "port": port, "server_frames": len(out_frames), "big": big,
                "hits": sorted(hits), "sentC": ci, "sstop": sstops[:2], "samples": samples}
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token-json", default=os.path.join(ROOT, "captures", "msdk_token.json"))
    ap.add_argument("--tails", default=TAILS)
    ap.add_argument("--template", default=TEMPLATE)
    ap.add_argument("--gateways", default="")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--openid-hex", default="", help="Garena open_id (32 hex) used inside report2 blob")
    args = ap.parse_args()

    token, openid, tail = load_target(args)
    tpl = json.load(open(args.template, encoding="utf-8"))
    frames = patch_template(tpl, token, openid, args.openid_hex)
    raw1001_bytes = raw1001.build(bytes.fromhex(json.load(open(FRAMESET, encoding="utf-8"))["raw1001"].replace(" ", "")), openid)
    log("[*] target token=%s... openid=%s tail=%04x frames=%d" % (token[:12], openid, tail, len(frames)))
    gws = DEFAULT_GATEWAYS
    if args.gateways:
        gws = []
        for part in args.gateways.split(","):
            a, b = part.split(":")
            gws.append((a, int(b)))
    evidence = {"token_head": token[:12], "openid": openid, "tail": "%04x" % tail,
                "template_frames": len(frames), "attempts": []}
    ok = False
    for ip, port in gws:
        res = run_gateway(ip, port, token, tail, frames, tpl["auth_header"], raw1001_bytes, args.timeout)
        evidence["attempts"].append(res)
        log("  %s:%d -> %s" % (ip, port, json.dumps(res, ensure_ascii=False)[:220]))
        if res.get("hits") and "CDNSharePicPath" in res.get("hits", []) and res.get("big", 0) >= 5:
            ok = True
            evidence.update({"gateway": "%s:%d" % (ip, port), "result": res,
                             "time": time.strftime("%Y-%m-%d %H:%M:%S")})
            log("[+] SESSION CREATED + LOBBY DATA on %s:%d" % (ip, port))
            break
    evidence["success"] = ok
    json.dump(evidence, open(EVIDENCE, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    log("[*] evidence -> %s" % EVIDENCE)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
