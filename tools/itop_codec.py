"""ITOP CODEC -- Tencent MSDK "encrypt=1" HTTP body codec (itop.kg.garena.vn).

Reversed 2026-10-22 from libMSDKCore.so (ARM64, GCloud::MSDK) via IDA Pro 9.3
headless decompilation, then verified against the captured mitm traffic in
captures/mitm_capture.jsonl.

ALGORITHM (identical for request bodies and response bodies):
    plaintext : UTF-8 JSON string (no trailing newline)
    sig       : the "sig" query parameter of the request URL
                (for /v2/auth/login it is 33 chars = 32-char md5 hex + "1";
                 other endpoints use the plain 32-char md5 hex)
    key       : md5_hex("MSDK_ENCRYPT" + SDK_KEY + sig)     -> 32 ASCII bytes
    cipher    : cipher[i] = plaintext[i] ^ key[i % 32]
    wire body : base64.b64encode(cipher) with newlines removed

SDK_KEY for itop.kg.garena.vn / gameid 1137 (assets/MSDKConfig.ini):
    4dfd535a3a2ef92644301c3e3ce87c9f

The request body is encrypted *after* the URL (and therefore sig) is known:
    key material = SDK_KEY + sig
    md5 input    = "MSDK_ENCRYPT" + key material
so encode() needs the sig of the URL the body will be sent with.

SIGNATURE (sig) FOR ENCRYPTED REQUESTS, verified against captures:
    auth/login   : sig = md5("/v2/auth/login?" + query + SDK_KEY + plaintext) + "1"
    other paths  : sig = md5("/v2/<path>?" + query + plaintext + SDK_KEY)
("query" = everything between "?" and "&sig=", in the exact order sent.)

libMSDKCore.so evidence (IDA addresses, symbol names from the .so):
  MSDKHTTPClient::Request                 sub_C5600 @0xC5600
      sees "&encrypt=1" in the URL ->
        sig part  = first 32 chars after "sig=" (33 for auth/login)
                    sub_C5DDC @0xC5DDC
        postData  = sub_166110(postData, SDK_KEY + sigpart)      <- encoder
        respData  = sub_1665AC(respBody,  SDK_KEY + sigpart)     <- decoder
  sub_166110 @0x166110 : out = b64_no_nl( sub_1668E0(postData,
                             md5_hex("MSDK_ENCRYPT" + keyMaterial)) )
  sub_1665AC @0x1665AC : out = sub_1668E0( b64_decode(respBody),
                             md5_hex("MSDK_ENCRYPT" + keyMaterial) )
  sub_1668E0 @0x1668E0 : byte-wise XOR of two strings, key repeated cyclically
                         (disasm: UDIV/MSUB i%keylen; EOR plain_key)
  sub_166880 @0x166880 : md5_hex(string)   (sub_164E84 MD5 update -> sub_16502C hex)
  sub_162594 @0x162594 : standard base64 encode (OpenSSL BIO_f_base64)
  sub_1627CC @0x1627CC : standard base64 decode
  sub_162888 @0x162888 : URL + sig builder for itop requests
  "MSDK_ENCRYPT"          @0x36DB00 string used by sub_166110/sub_1665AC
  "MSDK_ENCRYPT_STORAGE"  @0x36DAED config switch for other, *different* on-disk
                          codecs (MSDKBASE64ENCRYPTMSDK / MSDKTEAENCRYPTMSDK) --
                          those tags are NOT used for HTTP bodies; the HTTP body
                          codec is the XOR+base64 described above.

CLI
    # decode a single captured body
    python tools/itop_codec.py decode --sig <sig> --body <base64>

    # encode a JSON payload with a known sig
    python tools/itop_codec.py encode --sig <sig> --plaintext '{"a":1}'

    # decode all encrypt=1 request/response pairs from the mitm capture,
    # verify them, build our own login body, write captures/itop_decoded.json
    python tools/itop_codec.py extract
    python tools/itop_codec.py extract --live      # also POST it to itop

    # build (and optionally send) an encrypted /v2/auth/login request using the
    # Garena access token in captures/garena_token.json + app device uuid
    python tools/itop_codec.py build-login
    python tools/itop_codec.py build-login --live

    # offline self test on the captured records
    python tools/itop_codec.py selftest

stdlib only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SDK_KEY = "4dfd535a3a2ef92644301c3e3ce87c9f"
MSDK_URL = "https://itop.kg.garena.vn"
GAME_ID = "1137"
CHANNEL_ID = "10"
VERSION = "5.36.007"
CAPTURE = os.path.join(ROOT, "captures", "mitm_capture.jsonl")
GARENA_TOKEN = os.path.join(ROOT, "captures", "garena_token.json")
TOKEN_CACHE = os.path.join(ROOT, "captures", "token_cache_new.xml")
DECODED_OUT = os.path.join(ROOT, "captures", "itop_decoded.json")
BUILT_OUT = os.path.join(ROOT, "captures", "codec_built_login.json")

# The app's device fingerprint, exactly as leaked in the plaintext
# /v2/conf/get_conf body (captures/mitm_capture.jsonl).
DEVICE_UUID = os.environ.get("AOV_DEVICE_UUID", "00000000-0000-0000-0000-000000000000")
DEVICE_INFO = {
    "uuid": DEVICE_UUID,
    "device_language": "en",
    "app_version": "1.64.1.7.176857764",
    "screen_dpi": 1.5,
    "resolution": "1280*720",
    "trade_mark": "disable",
    "manufacturer": "disable",
    "model": "disable",
    "apn": "disable",
    "ram_info": "3150131200",
    "rom_info": "27940581376",
    "cpu_info": "-1",
    "imei": "",
    "qimei": "",
    "oaid": "",
    "xid": "",
    "qimei36": "",
}
# itop guest id used in the "seq" field of the captured session
GUEST_ID = "406da0d3-2196-43a8-a6ba-afc0b83fa670"


# --------------------------------------------------------------------------
# core codec
# --------------------------------------------------------------------------
def md5_hex(s):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return hashlib.md5(s).hexdigest()


def derive_key(sig, sdk_key=SDK_KEY):
    """Return the 32-byte repeating XOR key used for one request/response."""
    return md5_hex("MSDK_ENCRYPT" + sdk_key + sig).encode("ascii")


def xor_bytes(data, key):
    """Byte-wise XOR with a repeating key (sub_1668E0)."""
    if not key:
        raise ValueError("empty XOR key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _b64clean(body):
    """Normalise a wire base64 body: drop whitespace/newlines, fix padding."""
    if isinstance(body, bytes):
        body = body.decode("ascii", "strict")
    s = "".join(body.split())
    if not s:
        raise ValueError("empty body")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return s


def decode_body(body, sig, sdk_key=SDK_KEY):
    """Decode an encrypt=1 wire body into its plaintext bytes."""
    raw = base64.b64decode(_b64clean(body), validate=True)
    return xor_bytes(raw, derive_key(sig, sdk_key))


def encode_body(plaintext, sig, sdk_key=SDK_KEY):
    """Encode plaintext (bytes/str) into the encrypt=1 wire body string."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    cipher = xor_bytes(plaintext, derive_key(sig, sdk_key))
    return base64.b64encode(cipher).decode("ascii")


def sig_for_request(path, query, plaintext, sdk_key=SDK_KEY):
    """Recompute the sig of an encrypted itop request.

    path       : '/v2/auth/login', '/v2/notice/get_notice', ...
    query      : the query string as sent, WITHOUT sig
    plaintext  : UTF-8 JSON bytes/str body (decrypted)
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    head = path + "?" + query
    if path == "/v2/auth/login":
        return md5_hex(head.encode("utf-8") + sdk_key.encode("ascii") + plaintext) + "1"
    return md5_hex(head.encode("utf-8") + plaintext + sdk_key.encode("ascii"))


def split_sig(path):
    """'/x?y&sig=abc' -> ('/x?y', 'abc')  (sig must be the last param)."""
    marker = "&sig="
    i = path.rfind(marker)
    if i < 0:
        raise ValueError("no &sig= in path: %r" % path)
    return path[:i], path[i + len(marker):]


# --------------------------------------------------------------------------
# capture helpers
# --------------------------------------------------------------------------
def load_capture(path=CAPTURE):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def iter_encrypted_pairs(rows):
    """Yield (request_row, response_row_or_None) for every encrypt=1 request."""
    for i, row in enumerate(rows):
        if not row.get("body") or "encrypt=1" not in (row.get("path") or ""):
            continue
        resp = None
        for nxt in rows[i + 1:i + 6]:
            if nxt.get("rid") == row.get("rid") and nxt.get("resp_body"):
                resp = nxt
                break
        yield row, resp


def decode_record_pairs(rows, sdk_key=SDK_KEY):
    """Decode all encrypt=1 request/response pairs, self-verifying each."""
    out = []
    for req, resp in iter_encrypted_pairs(rows):
        path_no_sig, sig = split_sig(req["path"])
        plain = decode_body(req["body"], sig, sdk_key)
        try:
            plain_json = json.loads(plain.decode("utf-8"))
        except Exception:
            plain_json = None
        item = {
            "kind": "request",
            "rid": req.get("rid"),
            "ts": req.get("ts"),
            "host": req.get("host"),
            "path": req["path"],
            "sig": sig,
            "encoded_len": len(req["body"]),
            "plaintext_len": len(plain),
            "valid_json": plain_json is not None,
            "roundtrip_exact": encode_body(plain, sig, sdk_key) == _b64clean(req["body"]),
            "sig_recomputed_ok": sig_for_request(
                path_no_sig.split("?", 1)[0], path_no_sig.split("?", 1)[1], plain, sdk_key
            ) == sig,
            "plaintext": plain_json if plain_json is not None else plain.decode("utf-8", "replace"),
        }
        out.append(item)
        if resp is not None:
            rplain = decode_body(resp["resp_body"], sig, sdk_key)
            try:
                rjson = json.loads(rplain.decode("utf-8"))
            except Exception:
                rjson = None
            out.append({
                "kind": "response",
                "rid": resp.get("rid"),
                "ts": resp.get("ts"),
                "host": resp.get("host"),
                "path": req["path"],
                "sig": sig,
                "encoded_len": len(resp["resp_body"]),
                "plaintext_len": len(rplain),
                "valid_json": rjson is not None,
                "roundtrip_exact": encode_body(rplain, sig, sdk_key) == _b64clean(resp["resp_body"]),
                "plaintext": rjson if rjson is not None else rplain.decode("utf-8", "replace"),
            })
    return out


# --------------------------------------------------------------------------
# our own login request
# --------------------------------------------------------------------------
def load_garena_token(path=GARENA_TOKEN):
    data = json.load(open(path, encoding="utf-8"))["response"]
    return data["access_token"], str(data["open_id"])


def load_app_cached_garena_token(path=TOKEN_CACHE):
    """The Garena authToken cached by the *app* (shared_prefs token cache dump).

    Replaying /v2/auth/login with exactly this token returns the same
    device-bound MSDK game token the app obtained (verified live).
    """
    try:
        import xml.etree.ElementTree as ET
        root = ET.parse(path).getroot()
        for node in root.iter("string"):
            if node.get("name") == "com.garena.msdk.token" and node.text:
                tok = json.loads(node.text)
                return tok["authToken"], str(tok["openId"])
    except Exception:
        return None
    return None


def build_login_request(access_token=None, uid=None, device_info=None,
                        ts=None, seq=None, lang="", logintype=0, sdk_key=SDK_KEY):
    """Build a complete encrypted /v2/auth/login request (URL + sig + body)."""
    if access_token is None or uid is None:
        at, oid = load_garena_token()
        access_token = access_token or at
        uid = uid or oid
    ts = int(ts if ts is not None else time.time())
    seq = seq or "%s-%s-%d-%d" % (GAME_ID, GUEST_ID, ts, random.randint(1, 999))
    query = ("channelid=%s&encrypt=1&gameid=%s&lang=%s&os=1&seq=%s&ts=%d&version=%s"
             % (CHANNEL_ID, GAME_ID, lang, seq, ts, VERSION))
    plain_obj = {
        "device_info": device_info or dict(DEVICE_INFO),
        "channel_dis": "00000000",
        "scenes": 1,
        "scenes_version": 2,
        "channel_info": {
            "token": access_token,
            "uid": uid,
            "cgToken": "",
            "login_type": logintype,
        },
        "region": ["", "", ""],
    }
    plaintext = json.dumps(plain_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    path = "/v2/auth/login"
    sig = sig_for_request(path, query, plaintext, sdk_key)
    body = encode_body(plaintext, sig, sdk_key)
    url = MSDK_URL + path + "?" + query + "&sig=" + sig
    return {
        "method": "POST",
        "url": url,
        "path": path,
        "query": query,
        "sig": sig,
        "plaintext": plain_obj,
        "plaintext_len": len(plaintext),
        "body": body,
        "body_len": len(body),
        "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
    }


def http_post(url, body, timeout=25):
    req = urllib.request.Request(url, data=body.encode("ascii"), method="POST", headers={
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl.create_default_context()) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def decode_any_response(resp_bytes, sig):
    """itop responses to encrypt=1 requests are XOR+base64 encoded; errors may be JSON."""
    text = resp_bytes.decode("utf-8", "replace").strip()
    if text.startswith("{"):
        return {"encrypted": False, "plaintext": json.loads(text)}
    plain = decode_body(text, sig)
    return {"encrypted": True, "plaintext": json.loads(plain.decode("utf-8"))}


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_decode(args):
    sig = args.sig
    if args.body_file:
        body = open(args.body_file, "r", encoding="utf-8").read()
    else:
        body = args.body
    plain = decode_body(body, sig, args.sdk_key)
    sys.stdout.buffer.write(plain)
    sys.stdout.buffer.write(b"\n")
    return 0


def cmd_encode(args):
    if args.plaintext_file:
        plain = open(args.plaintext_file, "rb").read()
    else:
        plain = args.plaintext.encode("utf-8")
    print(encode_body(plain, args.sig, args.sdk_key))
    return 0


def _slim(item):
    """Copy a decoded record for the deliverable JSON."""
    return dict(item)


def cmd_extract(args):
    rows = load_capture(args.jsonl)
    items = decode_record_pairs(rows, args.sdk_key)
    reqs = [x for x in items if x["kind"] == "request"]
    resps = [x for x in items if x["kind"] == "response"]
    login_req = next((x for x in reqs if "/v2/auth/login" in x["path"]), None)
    login_resp = None
    if login_req is not None:
        login_resp = next((x for x in resps if x.get("rid") == login_req.get("rid")), None)
    built = build_login_request(sdk_key=args.sdk_key)
    doc = {
        "codec": "itop-encrypt1-xor-base64-v1",
        "description": (
            "wire body = base64_no_newlines(plaintext_json XOR "
            "md5_hex('MSDK_ENCRYPT' + SDK_KEY + sig)); "
            "sig is the request URL's sig query parameter. "
            "Reversed from libMSDKCore.so sub_166110 (encode) / sub_1665AC (decode)."
        ),
        "sdk_key": SDK_KEY,
        "source_capture": os.path.relpath(args.jsonl, ROOT),
        "generated_by": "python tools/itop_codec.py extract",
        "generated_at": int(time.time()),
        "records": [_slim(x) for x in items],
        "login_request": _slim(login_req) if login_req else None,
        "login_response": _slim(login_resp) if login_resp else None,
        "our_login_request": built,
        "verification": {
            "requests_decoded": len(reqs),
            "requests_valid_json": sum(1 for x in reqs if x["valid_json"]),
            "responses_decoded": len(resps),
            "responses_valid_json": sum(1 for x in resps if x["valid_json"]),
            "roundtrip_exact_all": all(x["roundtrip_exact"] for x in items),
            "sig_recomputed_all_requests": all(x["sig_recomputed_ok"] for x in reqs),
            "login_device_uuid": (
                login_req["plaintext"].get("device_info", {}).get("uuid")
                if login_req and isinstance(login_req.get("plaintext"), dict) else None
            ),
            "login_channel_token_prefix": (
                (login_req["plaintext"].get("channel_info", {}).get("token") or "")[:8]
                if login_req and isinstance(login_req.get("plaintext"), dict) else None
            ),
            "login_response_game_token": (
                login_resp["plaintext"].get("token") if login_resp and isinstance(login_resp.get("plaintext"), dict) else None
            ),
        },
    }
    if args.live:
        def _post_and_decode(req):
            status, raw = http_post(req["url"], req["body"])
            rec = {"http_status": status, "raw_len": len(raw)}
            try:
                rec.update(decode_any_response(raw, req["sig"]))
            except Exception as e:
                rec["decode_error"] = repr(e)
                rec["raw_head"] = raw[:200].decode("utf-8", "replace")
            return rec

        print("[*] POST %s" % built["url"])
        doc["our_login_response"] = _post_and_decode(built)
        r = doc["our_login_response"]
        print("[*] our token: HTTP %s ret=%s token=%s" % (
            r.get("http_status"), (r.get("plaintext") or {}).get("ret"),
            (r.get("plaintext") or {}).get("token")))

        app_tok = load_app_cached_garena_token()
        if app_tok:
            replay = build_login_request(access_token=app_tok[0], uid=app_tok[1],
                                         sdk_key=args.sdk_key)
            print("[*] replay app Garena token: POST %s" % replay["url"])
            rr = _post_and_decode(replay)
            doc["app_token_replay"] = {
                "garena_access_token": app_tok[0],
                "garena_open_id": app_tok[1],
                "request": replay,
                "result": rr,
            }
            print("[*] app-token replay: HTTP %s ret=%s token=%s" % (
                rr.get("http_status"), (rr.get("plaintext") or {}).get("ret"),
                (rr.get("plaintext") or {}).get("token")))
            vv = doc["verification"]
            vv["app_token_replay_ret"] = (rr.get("plaintext") or {}).get("ret")
            vv["app_token_replay_game_token"] = (rr.get("plaintext") or {}).get("token")
            vv["app_token_replay_matches_capture"] = (
                vv["app_token_replay_game_token"] == vv.get("login_response_game_token"))
        vv = doc["verification"]
        vv["our_login_ret"] = (doc["our_login_response"].get("plaintext") or {}).get("ret")
        vv["our_login_game_token"] = (
            doc["our_login_response"].get("plaintext") or {}).get("token")
    out = args.out
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
    v = doc["verification"]
    print("[*] decoded %d req + %d resp (json ok: %d/%d)" % (
        v["requests_decoded"], v["responses_decoded"],
        v["requests_valid_json"], v["responses_valid_json"]))
    print("[*] roundtrip_exact_all=%s sig_recomputed_all=%s" % (
        v["roundtrip_exact_all"], v["sig_recomputed_all_requests"]))
    print("[*] login uuid=%s channel_token_prefix=%s game_token=%s" % (
        v["login_device_uuid"], v["login_channel_token_prefix"], v["login_response_game_token"]))
    print("[*] wrote %s" % out)
    return 0


def cmd_build_login(args):
    built = build_login_request(access_token=args.token, uid=args.uid,
                                ts=args.ts, seq=args.seq, sdk_key=args.sdk_key)
    out = {"built": built}
    if args.live:
        print("[*] POST %s" % built["url"])
        status, raw = http_post(built["url"], built["body"])
        out["http_status"] = status
        out["raw_len"] = len(raw)
        try:
            dec = decode_any_response(raw, built["sig"])
            out["response"] = dec
            print("[*] HTTP %s ret=%s token=%s" % (
                status, dec["plaintext"].get("ret"), dec["plaintext"].get("token")))
        except Exception as e:
            out["decode_error"] = repr(e)
            out["raw_head"] = raw[:200].decode("utf-8", "replace")
            print("[!] decode failed: %r" % e)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print("[*] sig=%s body_len=%d url=%s" % (built["sig"], built["body_len"], built["url"]))
    print("[*] wrote %s" % args.out)
    return 0


def cmd_selftest(args):
    rows = load_capture(args.jsonl)
    items = decode_record_pairs(rows, args.sdk_key)
    reqs = [x for x in items if x["kind"] == "request"]
    resps = [x for x in items if x["kind"] == "response"]
    ok = True
    checks = []
    def check(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        checks.append((name, bool(cond), detail))
    check("requests decoded", len(reqs) >= 4, "%d" % len(reqs))
    check("all request json", all(x["valid_json"] for x in reqs), "")
    check("all response json", all(x["valid_json"] for x in resps), "")
    check("roundtrip exact", all(x["roundtrip_exact"] for x in items), "")
    check("sig recomputed", all(x["sig_recomputed_ok"] for x in reqs), "")
    login = next(x for x in reqs if "/v2/auth/login" in x["path"])
    p = login["plaintext"]
    check("login uuid", p["device_info"]["uuid"] == DEVICE_UUID, p["device_info"]["uuid"])
    check("login channel token", len(p["channel_info"]["token"]) >= 32,
          p["channel_info"]["token"][:8])
    check("login sig 33 chars", len(login["sig"]) == 33, login["sig"])
    # known-answer test: captured login body must decode byte-exactly
    check("known plaintext", p["channel_info"]["token"].startswith("a1169c63"),
          p["channel_info"]["token"][:8])
    # re-encode the known plaintext and compare with the captured wire body
    captured = next(r["body"] for r in rows
                    if r.get("body") and "/v2/auth/login" in (r.get("path") or ""))
    reencoded = encode_body(
        json.dumps(p, separators=(",", ":"), ensure_ascii=False), login["sig"], args.sdk_key)
    check("body re-encode", reencoded == _b64clean(captured), "%d chars" % len(reencoded))
    for name, good, detail in checks:
        print("[%s] %s %s" % ("OK" if good else "FAIL", name, detail))
    print("[*] selftest %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="Tencent MSDK itop encrypt=1 body codec")
    ap.add_argument("--sdk-key", default=SDK_KEY)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode", help="decode one captured wire body")
    d.add_argument("--sig", required=True)
    g = d.add_mutually_exclusive_group(required=True)
    g.add_argument("--body")
    g.add_argument("--body-file")
    d.set_defaults(func=cmd_decode)

    e = sub.add_parser("encode", help="encode plaintext with a known sig")
    e.add_argument("--sig", required=True)
    g = e.add_mutually_exclusive_group(required=True)
    g.add_argument("--plaintext")
    g.add_argument("--plaintext-file")
    e.set_defaults(func=cmd_encode)

    x = sub.add_parser("extract", help="decode the whole mitm capture -> itop_decoded.json")
    x.add_argument("--jsonl", default=CAPTURE)
    x.add_argument("--out", default=DECODED_OUT)
    x.add_argument("--live", action="store_true", help="also POST our rebuilt login body")
    x.set_defaults(func=cmd_extract)

    b = sub.add_parser("build-login", help="build our encrypted /v2/auth/login request")
    b.add_argument("--token", help="Garena access_token (default: captures/garena_token.json)")
    b.add_argument("--uid", help="Garena open_id")
    b.add_argument("--ts", type=int)
    b.add_argument("--seq")
    b.add_argument("--out", default=BUILT_OUT)
    b.add_argument("--live", action="store_true")
    b.set_defaults(func=cmd_build_login)

    s = sub.add_parser("selftest", help="offline known-answer test on the capture")
    s.add_argument("--jsonl", default=CAPTURE)
    s.set_defaults(func=cmd_selftest)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
