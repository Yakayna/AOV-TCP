"""LQ FRAMES -- parse the TSF4G-style game framing observed on LQ VN 1.64.1.7.

Wire format observed live (2026-10-22, port 6629), validated byte-for-byte:

  offset size  field
  0      2     magic        0x3366
  2      2     head_version 0x0008
  4      2     body_version 0x0008
  6      2     command      big-endian (0x4013 = 16403 main wrapper)
  8      4     flags        byte8 = is_response (0 client, 1 server)
  12     4     sequence     little-endian, per direction
  16     2     head_len     little-endian (22 normal, larger = header extension)
  18     1     ?            observed 0x00
  19     2     body_len     big-endian
  21     1     ?            observed 0x00/0x01
  head_len .. head_len+body_len  body (looks encrypted/compressed)

  head_len is 21 (no extension) or 22+ (extension). body_len lives at 19..20
  big-endian and is placed inside the header, not after it.

usage:
  python tools/lq_frames.py captures/relaunch.pcap --port 6629
  python tools/lq_frames.py captures/relaunch.pcap --json captures/frames.json
  python tools/lq_frames.py captures/relaunch.pcap --cmd 0x1001 --hex
"""
import sys, os, json, struct, argparse, collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcapmini import read_pcap

MAGIC = b"\x33\x66"


def streams(pkts, port):
    c = bytearray()
    s = bytearray()
    for p in pkts:
        if port not in (p["sport"], p["dport"]) or not p["payload"]:
            continue
        if p["dport"] == port:
            c += p["payload"]
        else:
            s += p["payload"]
    return bytes(c), bytes(s)


def parse(buf, direction):
    frames = []
    pos = 0
    while pos + 22 <= len(buf):
        if buf[pos:pos+2] != MAGIC:
            break
        hv, bv, cmd = struct.unpack_from(">HHH", buf, pos+2)
        flags = struct.unpack_from(">I", buf, pos+8)[0]
        seq = struct.unpack_from("<I", buf, pos+12)[0]
        hl = struct.unpack_from("<H", buf, pos+16)[0]
        f18 = buf[pos+18]
        bl = struct.unpack_from(">H", buf, pos+19)[0]
        f21 = buf[pos+21]
        total = hl + bl
        if hl < 21 or hl > 4096 or total > 100000 or pos + total > len(buf):
            break
        body = buf[pos+hl:pos+total]
        frames.append({
            "dir": direction, "off": pos, "cmd": cmd, "cmdhex": "0x%04x" % cmd,
            "flags": flags, "is_response": bool(flags >> 24),
            "seq": seq, "head_len": hl, "body_len": bl,
            "f18": f18, "f21": f21,
            "head_hex": buf[pos+21:pos+hl][:128].hex(" "),
            "body_hex": body[:64].hex(" "),
            "body": body,
        })
        pos += total
    return frames, len(buf) - pos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=6629)
    ap.add_argument("--json")
    ap.add_argument("--cmd", help="filter command, e.g. 0x1001")
    ap.add_argument("--hex", action="store_true", help="hex dump bodies of matching cmd")
    ap.add_argument("--limit", type=int, default=12)
    args = ap.parse_args()

    pkts = read_pcap(args.pcap)
    c, s = streams(pkts, args.port)
    cf, cleft = parse(c, "C>S")
    sf, sleft = parse(s, "S>C")
    frames = cf + sf

    print("[*] %s port %d: C>S %d bytes/%d frames (left %d), S>C %d bytes/%d frames (left %d)"
          % (args.pcap, args.port, len(c), len(cf), cleft, len(s), len(sf), sleft))
    hist = collections.Counter(f["cmdhex"] for f in frames)
    print("[*] commands:", ", ".join("%s x%d" % (k, v) for k, v in hist.most_common()))
    print()
    print("%-4s %-7s %-6s %-5s %-4s %-8s %-6s %s" % ("DIR", "CMD", "SEQ", "RESP", "HL", "BL", "FLAGS", "BODY HEAD"))
    for f in frames[:args.limit]:
        print("%-4s %-7s %-6d %-5s %-4d %-8d 0x%08x %s" % (
            f["dir"], f["cmdhex"], f["seq"], "Y" if f["is_response"] else "N",
            f["head_len"], f["body_len"], f["flags"], f["body_hex"][:40]))

    if args.cmd:
        want = int(args.cmd, 16) if args.cmd.startswith("0x") else int(args.cmd)
        sel = [f for f in frames if f["cmd"] == want]
        print("\n[*] %d frames with cmd %s" % (len(sel), hex(want)))
        for f in sel:
            print("--", f["dir"], "seq", f["seq"], "head_len", f["head_len"], "body_len", f["body_len"])
            if f["head_len"] > 22:
                print("   head extra:", f["head_hex"])
            if args.hex:
                print("   body:", f["body"].hex(" "))

    if args.json:
        for f in frames:
            f["body"] = f["body"][:256].hex(" ") if f["body"] else ""
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"pcap": args.pcap, "port": args.port, "frames": frames}, fh, indent=1)
        print("\n[+] %d frames -> %s" % (len(frames), args.json))


if __name__ == "__main__":
    main()
