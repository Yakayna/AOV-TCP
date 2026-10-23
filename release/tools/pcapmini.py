"""Minimal classic-pcap reader. Standard library only.

Supports LINKTYPE: ETHERNET (1), RAW (101), LINUX_SLL (113), LINUX_SLL2 (276).
pcapng is NOT supported -- convert first:
    tshark -r in.pcapng -w out.pcap
"""
import struct

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\x4d\x3c\x00\x00": ">",
}


def _ipv4(data):
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total = struct.unpack(">H", data[2:4])[0]
    if total < ihl:
        total = len(data)
    proto = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    body = data[ihl:total]
    sport = dport = None
    payload = b""
    flags = 0
    seq = 0
    if proto == 6 and len(body) >= 20:
        sport, dport, seq, _ack = struct.unpack(">HHII", body[0:12])
        off = (body[12] >> 4) * 4
        flags = body[13]
        payload = body[off:]
        l4 = "TCP"
    elif proto == 17 and len(body) >= 8:
        sport, dport = struct.unpack(">HH", body[0:4])
        payload = body[8:]
        l4 = "UDP"
    elif proto == 1:
        l4 = "ICMP"
    else:
        l4 = "IP/%d" % proto
    return {"proto": l4, "src": src, "dst": dst, "sport": sport, "dport": dport,
            "payload": payload, "seq": seq, "flags": flags, "ip_len": total}


def _link_payload(linktype, frame):
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        off = 14
        while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 4:
            ethertype = struct.unpack(">H", frame[off + 2:off + 4])[0]
            off += 4
        return frame[off:] if ethertype == 0x0800 else None
    if linktype == LINKTYPE_RAW:
        return frame
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        return frame[16:] if struct.unpack(">H", frame[14:16])[0] == 0x0800 else None
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        return frame[20:] if struct.unpack(">H", frame[0:2])[0] == 0x0800 else None
    return None


def read_pcap(path):
    pkts = []
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            raise ValueError("not a pcap file (too short)")
        magic = hdr[0:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng detected. convert first: tshark -r in.pcapng -w out.pcap")
        if magic not in MAGICS:
            raise ValueError("unknown pcap magic %r" % (magic,))
        endian = MAGICS[magic]
        _vmaj, _vmin, _tz, _sig, _snap, network = struct.unpack(endian + "HHiIII", hdr[4:24])
        linktype = network & 0x0FFFFFFF
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", rh)
            frame = f.read(incl)
            if len(frame) < incl:
                break
            ip = _link_payload(linktype, frame)
            if not ip:
                continue
            rec = _ipv4(ip)
            if not rec:
                continue
            rec["ts"] = ts_sec + ts_usec / 1e6
            rec["orig"] = orig
            pkts.append(rec)
    return pkts


def flow_key(p):
    a, b = (p["src"], p["sport"]), (p["dst"], p["dport"])
    return tuple(sorted([a, b])) + (p["proto"],)


def tcp_flag_str(flags):
    names = []
    for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"),
                      (0x04, "RST"), (0x20, "URG")):
        if flags & bit:
            names.append(name)
    return ",".join(names) or "-"
