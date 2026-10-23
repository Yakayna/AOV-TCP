# -*- coding: utf-8 -*-
"""HOLD LOBBY 24/7 -- giu session lobby song song khi cua so CMD con mo.

Vong lap:
  1) Ping lai gateway bang f0 (auth lai token) -> neu server van tra lobby data
     thi session con song -> ONLINE, ngu 90s roi lap lai.
  2) Neu ping khong thay lobby -> chay lai replay template de tao session moi
     (clientless_lobby_replay.py). Neu tao duoc -> ONLINE.
  3) That bai -> doi 30s thu lai; sau nhieu lan lien tiep in huong dan chay lai
     LUQ_Login.cmd (token co the het han).

Chay: LUQ_Online.cmd  (hoac python tools/hold_lobby.py)
Dung Ctrl+C de dung.
"""
import json, os, random, socket, struct, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lq_decrypt
import raw1001
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
HEAD = bytes.fromhex("fffe02073534353008360b0b2547")
MTOKEN = os.path.join(ROOT, "captures", "msdk_token.json")
TAILS = os.path.join(ROOT, "captures", "token_tails.json")
FRAMESET = os.path.join(ROOT, "captures", "connect_6670_frameset.json")
F0SET = os.path.join(ROOT, "captures", "f0_frameset.json")
LOGF = os.path.join(ROOT, "captures", "hold_log.txt")
GATEWAYS = [("148.222.90.36", 6629), ("148.222.90.43", 6630), ("148.222.90.181", 6629),
            ("148.222.90.120", 6630), ("148.222.90.165", 6629)]
PING_INTERVAL = 90
RETRY_INTERVAL = 30


def log(msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOGF, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


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
                            "seq": struct.unpack_from("<I", buf, i + 12)[0], "raw": buf[i:i+hl+bl]})
                i += hl + bl; continue
        i += 1
    return out


def recv_until(s, seconds):
    s.settimeout(0.03)
    d = b""; t0 = time.time()
    while time.time() - t0 < seconds:
        try:
            ch = s.recv(65536)
            if not ch:
                break
            d += ch
        except socket.timeout:
            continue
        except Exception:
            break
    return d


def load_session():
    tok = json.load(open(MTOKEN, encoding="utf-8"))["response"]
    tails = json.load(open(TAILS, encoding="utf-8"))
    token = tok["token"]
    if token not in tails:
        return None
    fset = json.load(open(FRAMESET, encoding="utf-8"))
    f0set = json.load(open(F0SET, encoding="utf-8"))
    return {"token": token, "openid": str(tok["openid"]), "tail": int(tails[token], 16),
            "raw1001": raw1001.build(bytes.fromhex(fset["raw1001"].replace(" ", "")), str(tok["openid"])),
            "auth_header": bytes.fromhex(fset["raw2001_header"].replace(" ", "")),
            "f0_header": bytes.fromhex(f0set["header"]), "f0_payload": bytes.fromhex(f0set["payload"]),
            "f0_struct": bytes.fromhex(f0set["f0_struct"]),
            "openid_hex": str(tok.get("uid") or "")}


def auth(s, ses, key):
    core = ses["token"][2:]
    iv = ecb(key, HEAD + struct.pack(">H", ses["tail"]))
    pt = core.encode() + b"\x00" * (64 - len(core) - 7) + bytes([random.randrange(256)]) + b"tsf4g" + b"\x07"
    body = iv + enc(key, iv, pt)
    h = bytearray(ses["auth_header"]); struct.pack_into(">H", h, 19, len(body))
    s.sendall(bytes(h) + body)
    return parse(recv_until(s, 1.0))


def ping_gateway(ses, ip, port):
    try:
        s = socket.create_connection((ip, port), timeout=4)
    except Exception:
        return None
    try:
        s.sendall(ses["raw1001"])
        key = None
        for f in parse(recv_until(s, 0.9)):
            if f["cmd"] == 0x1002 and len(f["raw"]) >= 39:
                key = f["raw"][23:39]
        if not key:
            return None
        fr = auth(s, ses, key)
        if not any(x["cmd"] == 0x2002 for x in fr):
            return {"ip": ip, "port": port, "auth": False}
        iv = ecb(key, ses["f0_struct"])
        payload = ses["f0_payload"][:103] + os.urandom(3) + b"tsf4g" + bytes([9])
        body = iv + enc(key, iv, payload)
        hh = bytearray(ses["f0_header"]); struct.pack_into(">H", hh, 19, len(body)); struct.pack_into("<I", hh, 12, 3)
        s.sendall(bytes(hh) + body)
        frames = parse(recv_until(s, 3.0))
        big = 0; hits = set()
        for x in frames:
            if x["cmd"] == 0x4013:
                bb = x["raw"][x["hl"]:]
                try:
                    p3 = dec(key, bb[:16], bb[16:])
                except Exception:
                    continue
                if len(p3) > 1000:
                    big += 1
                txt = p3.decode("utf-8", "ignore")
                for kw in ("CDNSharePicPath", "INVALID_KEY", "aovcloud"):
                    if kw in txt:
                        hits.add(kw)
        return {"ip": ip, "port": port, "auth": True, "frames": len(frames), "big": big, "hits": sorted(hits)}
    finally:
        try:
            s.close()
        except Exception:
            pass


def create_session(ses):
    cmd = [PY, os.path.join(ROOT, "tools", "clientless_lobby_replay.py"),
           "--token-json", os.path.relpath(MTOKEN, ROOT)]
    if ses.get("openid_hex"):
        cmd += ["--openid-hex", ses["openid_hex"]]
    log("chay tao session: clientless_lobby_replay.py")
    try:
        p = subprocess.run(cmd, cwd=ROOT, timeout=240)
        ok = p.returncode == 0
    except Exception as e:
        log("tao session loi: %s" % e)
        ok = False
    if ok:
        try:
            ev = json.load(open(os.path.join(ROOT, "captures", "lobby_session_evidence.json"), encoding="utf-8"))
            r = ev.get("result") or {}
            log("SESSION CREATED: %s frames=%s big=%s hits=%s" % (ev.get("gateway"), r.get("server_frames"), r.get("big"), r.get("hits")))
        except Exception:
            pass
    return ok


def main():
    log("=" * 60)
    log("HOLD LOBBY 24/7 bat dau. Cua so nay phai mo. Ctrl+C de dung.")
    ses = load_session()
    if not ses:
        log("LOI: khong tim thay token/tail. Hay chay LUQ_Login.cmd truoc.")
        return 1
    log("token=%s... openid=%s tail=%04x" % (ses["token"][:12], ses["openid"], ses["tail"]))
    fails = 0
    while True:
        online = False
        for ip, port in GATEWAYS:
            r = ping_gateway(ses, ip, port)
            if r and r.get("auth") and (r.get("big", 0) > 0):
                log("ONLINE | %s:%d frames=%d big=%d" % (ip, port, r["frames"], r["big"]))
                online = True
                break
        if not online:
            log("Session chua online -> thu tao lai session...")
            if create_session(ses):
                online = True
        if online:
            fails = 0
            time.sleep(PING_INTERVAL)
        else:
            fails += 1
            log("OFFLINE (lan %d) - thu lai sau %ds" % (fails, RETRY_INTERVAL))
            if fails in (3, 10, 20):
                log("GOI Y: neu that bai mai, chay lai LUQ_Login.cmd (token co the het han).")
            time.sleep(RETRY_INTERVAL)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[hold] dung boi nguoi dung", flush=True)
