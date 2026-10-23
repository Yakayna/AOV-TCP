"""LQ DECRYPT -- decrypt LQ 1.64.1.7 game-channel bodies.

Reverse-engineered 2026-10-22 from a live session:

  handshake: S>C cmd 0x1002 header extension carries the session key:
      <xx> <len=0x10> <16 ASCII chars> ...
  body     : AES-128-CBC
      IV        = first 16 bytes of the body (sent in clear)
      key       = the 16 ASCII chars from the handshake
      ciphertext= body[16:]
      plaintext ends with the ASCII tag "tsf4g" then padding

usage:
  python tools/lq_decrypt.py captures/relaunch.pcap --out captures/dec
  python tools/lq_decrypt.py captures/relaunch.pcap --key Sba7gRZeTxrVIpwy
"""
import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcapmini import read_pcap
import lq_frames

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


def aes128_cbc_decrypt(key, iv, data):
    if HAVE_CRYPTO:
        c = Cipher(algorithms.AES(key), modes.CBC(iv))
        d = c.decryptor()
        return d.update(data) + d.finalize()
    # pure-python AES is out of scope; use the helper script instead
    raise SystemExit("[!] cryptography module missing. pip install cryptography")


def aes128_cbc_encrypt(key, iv, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    e = c.encryptor()
    return e.update(data) + e.finalize()


def find_key(frames):
    for f in frames:
        if f["cmd"] == 0x1002 and f["dir"] == "S>C":
            ext = bytes.fromhex(f["head_hex"].replace(" ", ""))
            for i in range(len(ext) - 17):
                if ext[i] == 0x10:
                    cand = ext[i+1:i+17]
                    if all(32 <= c < 127 for c in cand):
                        return cand.decode("ascii")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=6629)
    ap.add_argument("--key", help="override 16-char session key")
    ap.add_argument("--out", default="captures/dec")
    args = ap.parse_args()

    pkts = read_pcap(args.pcap)
    c, s = lq_frames.streams(pkts, args.port)
    frames = []
    for buf, d in ((c, "C>S"), (s, "S>C")):
        fr, left = lq_frames.parse(buf, d)
        frames += fr
    key = args.key or find_key(frames)
    if not key:
        raise SystemExit("[!] key not found in handshake; pass --key")
    print("[*] frames %d, key %r" % (len(frames), key))
    os.makedirs(args.out, exist_ok=True)

    rows = []
    ok = 0
    tag = b"tsf4g"
    for f in frames:
        body = f["body"]
        if len(body) < 32 or len(body) % 16:
            continue
        try:
            pt = aes128_cbc_decrypt(key.encode(), body[:16], body[16:])
        except Exception as e:
            continue
        has_tag = tag in pt[-24:]
        printable = sum(1 for x in pt if 32 <= x < 127 or x in (9, 10, 13)) / float(len(pt))
        if has_tag:
            ok += 1
        name = "%s_%s_%05d.bin" % (f["dir"].replace(">", ""), f["cmdhex"], f["seq"])
        path = os.path.join(args.out, name)
        with open(path, "wb") as fh:
            fh.write(pt)
        rows.append({"file": name, "dir": f["dir"], "cmd": f["cmdhex"], "seq": f["seq"],
                     "ct_len": len(body), "tag": has_tag, "printable": round(printable, 3),
                     "head_hex": pt[:32].hex(" ")})
    rows.sort(key=lambda r: (-len(r["head_hex"]), r["seq"]))
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)
    print("[*] decrypted %d bodies, tag ok %d" % (len(rows), ok))
    print("[*] wrote %s + manifest.json" % args.out)
    for r in rows[:8]:
        print("  ", r["file"], "tag", r["tag"], "printable", r["printable"], "|", r["head_hex"][:60])


if __name__ == "__main__":
    main()
