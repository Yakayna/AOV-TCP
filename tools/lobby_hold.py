# -*- coding: utf-8 -*-
"""
Liên Quân Mobile - clientless lobby holder v2 (realm assignment -> gateway reports)
- Dùng MSDK token trong captures/msdk_token.json
- Tail IV-struct: lấy từ captures/token_tails.json (cache), registry hoặc 686a
- Flow: realm 6670 auth -> 3 device reports -> assignment IP:port
        -> gateway auth -> 3 reports -> nhận dữ liệu lobby 0x4013 -> giữ phiên
- Chạy mãi, tự reconnect; Ctrl+C dừng.
"""
import json, os, socket, struct, sys, time, random, datetime, re, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import lq_decrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TOKEN_FILE = os.path.join(ROOT, "captures", "msdk_token.json")
FS_FILE = os.path.join(ROOT, "captures", "connect_6670_frameset.json")
TPL_FILE = os.path.join(ROOT, "captures", "realm_templates.json")
TAILS_FILE = os.path.join(ROOT, "captures", "token_tails.json")
REGISTRY_FILE = os.path.join(ROOT, "captures", "registered_tokens.json")
EVIDENCE_FILE = os.path.join(ROOT, "captures", "lobby_hold_evidence.json")
LOG_FILE = os.path.join(ROOT, "captures", "lobby_hold.log")
REALM = [("148.222.93.33", 6670), ("148.222.93.36", 6670), ("148.222.93.38", 6670)]
HEAD = bytes.fromhex("fffe02073534353008360b0b2547")
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

def log(msg):
    line = "[%s] %s" % (datetime.datetime.now().strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(line + "\n")
    except Exception: pass

def ecb(k, d):
    c = Cipher(algorithms.AES(k), modes.ECB()).encryptor(); return c.update(d) + c.finalize()
def enc(k, iv, d): return lq_decrypt.aes128_cbc_encrypt(k, iv, d)
def dec(k, iv, d):
    try: return lq_decrypt.aes128_cbc_decrypt(k, iv, d)
    except Exception: return None

def parse(buf):
    out = []; i = 0
    while i + 21 <= len(buf):
        if buf[i] == 0x33 and buf[i+1] == 0x66:
            hl = struct.unpack_from("<H", buf, i+16)[0]; bl = struct.unpack_from(">H", buf, i+19)[0]
            if 21 <= hl <= 8192 and bl <= 65535 and i + hl + bl <= len(buf):
                out.append({"hl": hl, "bl": bl, "cmd": int.from_bytes(buf[i+6:i+8], "big"),
                            "seq": struct.unpack_from("<I", buf, i+12)[0], "raw": buf[i:i+hl+bl]})
                i += hl + bl; continue
        i += 1
    return out

def recv(s, t=0.3):
    s.settimeout(0.03); d = b""; t0 = time.time()
    while time.time() - t0 < t:
        try: ch = s.recv(65536)
        except socket.timeout: continue
        except Exception: break
        if not ch: break
        d += ch
    return d

def load_all():
    fs = json.load(open(FS_FILE, encoding="utf-8"))
    tokj = json.load(open(TOKEN_FILE, encoding="utf-8"))["response"]
    tpl = json.load(open(TPL_FILE, encoding="utf-8"))
    tails = {}
    try: tails = json.load(open(TAILS_FILE, encoding="utf-8"))
    except Exception: pass
    token = tokj.get("token")
    tail_hex = tails.get(token)
    if not tail_hex:
        try:
            reg = json.load(open(REGISTRY_FILE, encoding="utf-8")).get(str(tokj.get("openid")))
            if reg and reg.get("token") == token: tail_hex = reg.get("tail")
        except Exception: pass
    if not tail_hex:
        tail_hex = "686a"
        log("WARN: chưa có tail cho token này, thử 686a (có thể sai -> brute sau)")
    return fs, tokj, tpl, token, int(tail_hex, 16)

def build(hdr_hex, pt, key, seq, iv_hex):
    hdr = bytearray(bytes.fromhex(hdr_hex)); ivs = bytes.fromhex(iv_hex)
    iv = ecb(key, ivs); body = iv + enc(key, iv, pt)
    struct.pack_into(">H", hdr, 19, len(body)); struct.pack_into("<I", hdr, 12, seq)
    return bytes(hdr) + body

def auth(s, raw1001, core, tail):
    s.sendall(raw1001); d = recv(s, 0.8); key = None
    for f in parse(d):
        if f["cmd"] == 0x1002 and len(f["raw"]) >= 39: key = f["raw"][23:39]
    if not key: return None, parse(d)
    iv = ecb(key, HEAD + struct.pack(">H", tail))
    pt = core.encode() + b"\x00"*(64-len(core)-7) + b"\x17" + b"tsf4g" + b"\x07"
    body = iv + enc(key, iv, pt)
    h = bytearray(bytes.fromhex(FS_FILE and json.load(open(FS_FILE, encoding="utf-8"))["raw2001_header"].replace(" ", "")))
    struct.pack_into(">H", h, 19, len(body))
    s.sendall(bytes(h) + body); d2 = recv(s, 0.9)
    return key, parse(d2)

def realm_assign(raw1001, core, tail, tpl):
    for rip in REALM:
        try: s = socket.create_connection(rip, timeout=5)
        except Exception: continue
        key, fr = auth(s, raw1001, core, tail)
        if not key or not any(x["cmd"] == 0x2002 for x in fr):
            s.close(); continue
        reports = tpl["reports"]
        for n, r in enumerate(reports):
            s.sendall(build(r["hdr"], bytes.fromhex(r["payload"]), key, r["seq"], r["iv"]))
        time.sleep(0.25); d = recv(s, 1.2); fr = parse(d)
        assigned = None
        for f in fr:
            if f["cmd"] == 0x4013:
                b = f["raw"][f["hl"]:]; pt = dec(key, b[:16], b[16:])
                if pt:
                    m = re.search(rb"(\d+\.\d+\.\d+\.\d+)\x00", pt)
                    if m:
                        port = struct.unpack(">H", pt[m.end():m.end()+2])[0]
                        assigned = (m.group(1).decode(), port)
        if tpl.get("cstop"):
            c = tpl["cstop"]
            try: s.sendall(build(c["hdr"], bytes.fromhex(c["payload"]), key, c["seq"], c["iv"]))
            except Exception: pass
        s.close()
        if assigned: return assigned
    return None

def ensure_tail_for_token(token):
    """Dò tail 16-bit cho token hiện tại (chạy brute_tail.py) rồi đọc lại cache."""
    log("Gateway báo tail IV sai — đang dò tail cho token %s... (~1-3 phút)" % token[:12])
    script = os.path.join(ROOT, "tools", "brute_tail.py")
    try: subprocess.run([sys.executable, script], cwd=ROOT, timeout=1200)
    except Exception as e: log("brute_tail lỗi: %s" % e)
    try:
        tails = json.load(open(TAILS_FILE, encoding="utf-8"))
        if token in tails:
            log("TAIL OK: %s" % tails[token]); return int(tails[token], 16)
    except Exception: pass
    log("Không dò được tail (token/acc có thể không hợp lệ hoặc acc bị ban).")
    return None

def run_hold(seconds=None):
    fs, tokj, tpl, token, tail = load_all()
    core = token[2:40]
    openid = str(tokj.get("openid"))
    raw1001 = bytearray(bytes.fromhex(fs["raw1001"].replace(" ", "")))
    i = bytes(raw1001).find(b"OPENID_PLACEHOLD")
    if i >= 0: raw1001[i:i+16] = openid.encode()
    start_all = time.time(); cycle = 0; total_frames = 0; lobby_strings = set()
    while True:
        if seconds is not None and time.time() - start_all >= seconds:
            log("reached --seconds limit, stopping"); break
        cycle += 1
        try:
            assigned = realm_assign(bytes(raw1001), core, tail, tpl)
            if not assigned:
                log("realm assignment FAILED, retry 1s..."); time.sleep(1); continue
            ip, port = assigned
            s = socket.create_connection(assigned, timeout=6)
            key, fr = auth(s, bytes(raw1001), core, tail)
            if not key or not any(x["cmd"] == 0x2002 for x in fr):
                sstop_hex = ""
                for f in fr:
                    if f["cmd"] == 0x5002:
                        sstop_hex = f["raw"][f["hl"]:].hex(" ")
                        log("gateway auth S-Stop %s" % sstop_hex)
                s.close()
                if sstop_hex.startswith("00000008"):
                    new_tail = ensure_tail_for_token(token)
                    if new_tail is not None:
                        tail = new_tail; continue
                if sstop_hex.startswith("00000011"):
                    log("Token/acc không hợp lệ hoặc acc bị ban — nên dùng acc khác.")
                log("gateway auth failed at %s:%d; retry 1s..." % (ip, port)); time.sleep(1); continue
            for r in tpl["reports"]:
                s.sendall(build(r["hdr"], bytes.fromhex(r["payload"]), key, r["seq"], r["iv"]))
            log("LOGIN OK | openid=%s | token=%s... | gateway=%s:%d | tail=%04x" % (openid, token[:12], ip, port, tail))
            s.settimeout(0.05); buf = b""; hold_start = time.time(); frames = 0; big = 0
            last_status = 0; sstop = None
            while True:
                if seconds is not None and time.time() - start_all >= seconds: break
                try: ch = s.recv(65536)
                except socket.timeout: ch = b""
                except Exception: break
                if ch:
                    buf += ch; fr2 = parse(buf)
                    if fr2:
                        used = sum(x["hl"] + x["bl"] for x in fr2); buf = buf[used:]
                        for f in fr2:
                            frames += 1; total_frames += 1
                            if f["cmd"] == 0x5002: sstop = f["raw"][f["hl"]:].hex(" ")
                            if f["cmd"] == 0x4013:
                                b = f["raw"][f["hl"]:]; p2 = dec(key, b[:16], b[16:])
                                if p2:
                                    if len(p2) > 1000: big += 1
                                    txt = p2.decode("utf-8", "ignore")
                                    for kw in ("CDNSharePicPath", "INVALID_KEY", "Trang", "Ocak", "Ngôn"):
                                        if kw in txt: lobby_strings.add(kw)
                now = time.time()
                if now - last_status >= 5:
                    last_status = now
                    log("LOBBY HOLD | cycle=%d frames=%d big=%d uptime=%ds | lobby_strings=%s" % (
                        cycle, frames, big, int(now - hold_start), ",".join(sorted(lobby_strings)) or "-"))
                    try:
                        json.dump({"openid": openid, "token_head": token[:12], "tail": "%04x" % tail,
                                   "gateway": "%s:%d" % (ip, port), "cycles": cycle, "frames": frames,
                                   "big_frames": big, "total_frames": total_frames,
                                   "hold_seconds": int(now - hold_start), "sstop": sstop,
                                   "lobby_strings": sorted(lobby_strings),
                                   "updated": datetime.datetime.now().isoformat(timespec="seconds")},
                                  open(EVIDENCE_FILE, "w", encoding="utf-8"), indent=1)
                    except Exception: pass
                if sstop:
                    log("server S-Stop code=%s (frames=%d)" % (sstop, frames))
                    if sstop.startswith("00000011") and frames < 20:
                        log("=> Token/acc mới CHƯA ĐĂNG KÝ world. Cần 1 lần đăng nhập acc này qua game client (hoặc chờ mình hoàn thiện handshake world).")
                    if sstop.startswith("00000008"):
                        log("=> Tail IV sai: script sẽ tự dò lại tail cho token này.")
                    break
            s.close()
        except KeyboardInterrupt:
            log("stopped by user (Ctrl+C)"); break
        except Exception as e:
            log("session error: %s -> reconnect 1s" % e); time.sleep(1)
        time.sleep(0.5)

if __name__ == "__main__":
    try:
        log("=" * 60); log("LIÊN QUÂN MOBILE — CLIENTLESS LOBBY HOLD v2"); log("=" * 60)
        run_hold()
    except KeyboardInterrupt:
        log("stopped")
