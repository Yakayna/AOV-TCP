# -*- coding: utf-8 -*-
"""Tao template frameset tu pcap cua chinh ban (KHONG kem token).

Input : pcap bat phien app dang nhap (realm 6670 va/hoac gateway 6629/6630)
Output: captures/connect_6670_frameset.json  (raw1001 + raw2001 header)

Cach dung:
    python tools/make_frameset.py captures/app_login.pcap
"""
import json, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcapmini import read_pcap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "captures", "app_login.pcap")
MARKER = b"OPENID_PLACEHOLD"   # 16 bytes, se duoc thay bang game openid khi chay


def parse(buf):
    out = []; i = 0
    while i + 21 <= len(buf):
        if buf[i] == 0x33 and buf[i + 1] == 0x66:
            hl = struct.unpack_from("<H", buf, i + 16)[0]
            bl = struct.unpack_from(">H", buf, i + 19)[0]
            if 21 <= hl <= 8192 and bl <= 65535 and i + hl + bl <= len(buf):
                out.append({"hl": hl, "bl": bl,
                            "cmd": int.from_bytes(buf[i + 6:i + 8], "big"),
                            "raw": buf[i:i + hl + bl]})
                i += hl + bl; continue
        i += 1
    return out


def collect(pcap):
    flows = {}
    for x in read_pcap(pcap):
        if x.get("proto") != "TCP" or not x.get("payload"):
            continue
        k = (x["src"], x["sport"], x["dst"], x["dport"])
        flows.setdefault(k, b"")
    for x in read_pcap(pcap):
        if x.get("proto") != "TCP" or not x.get("payload"):
            continue
        k = (x["src"], x["sport"], x["dst"], x["dport"])
        flows[k] += x["payload"]
    return flows


def find_raw1001(flows):
    for k, buf in flows.items():
        if k[3] not in (6670, 6629, 6630) and k[1] not in (6670, 6629, 6630):
            continue
        for f in parse(buf):
            if f["cmd"] == 0x1001:
                raw = bytearray(f["raw"])
                # game openid la 16 ky tu ASCII so nam trong goi 0x1001
                import re
                m = re.search(rb"\d{16}", bytes(raw))
                if m:
                    raw[m.start():m.start() + 16] = MARKER
                else:
                    raw[38:54] = MARKER
                return bytes(raw)
    return None


def find_raw2001_header(flows):
    for k, buf in flows.items():
        if k[3] not in (6670, 6629, 6630):
            continue
        for f in parse(buf):
            if f["cmd"] == 0x2001:
                return f["raw"][:f["hl"]]
    return None


def main():
    if not os.path.exists(PCAP):
        print("[!] khong thay pcap:", PCAP)
        print("    python tools/make_frameset.py <duong_dan_pcap>")
        return 1
    flows = collect(PCAP)
    raw1001 = find_raw1001(flows)
    raw2001 = find_raw2001_header(flows)
    if not raw1001 or not raw2001:
        print("[!] khong tim thay 0x1001/0x2001 trong pcap (can bat dung luc app login)")
        return 1
    out = {
        "purpose": "sanitized replay template (no token, no account data)",
        "raw1001": raw1001.hex(),
        "raw2001_header": raw2001.hex(),
    }
    os.makedirs(os.path.join(ROOT, "captures"), exist_ok=True)
    dst = os.path.join(ROOT, "captures", "connect_6670_frameset.json")
    json.dump(out, open(dst, "w", encoding="utf-8"), indent=1)
    print("[+] wrote", dst)
    print("    raw1001 len", len(raw1001), "| openid placeholder:", MARKER.decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
