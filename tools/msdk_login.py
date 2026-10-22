"""MSDK CLIENTLESS LOGIN -- Garena token -> Tencent MSDK game token.

Reversed from libMSDKCore.so (IDA) + live endpoint verification 2026-10-22:

  POST https://itop.kg.garena.vn/v2/auth/login
  query: channelid=10&gameid=1137&lang=en&os=1&ts=<unix>&version=5.36.007
  sig  : md5("/v2/auth/login?" + query + postBody + MSDK_SDK_KEY)   (32 hex lowercase)
  body : {"channel_dis":"Garena","scenes":1,"scenes_version":2,"region":"VN",
          "channel_info":{"token":"<Garena access_token>"}}

  success -> ret=0, openid (game openid, e.g. <game_openid>), token (MSDK game token),
             uid (Garena open_id), channel_id 10 ...

Config source: assets/MSDKConfig.ini
  MSDK_URL       = https://itop.kg.garena.vn
  MSDK_GAME_ID   = 1137
  MSDK_SDK_KEY   = 4dfd535a3a2ef92644301c3e3ce87c9f
  GARENA channel = 10
"""
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GARENA_TOKEN = os.path.join(ROOT, "captures", "garena_token.json")
OUT = os.path.join(ROOT, "captures", "msdk_token.json")
MSDK_URL = "https://itop.kg.garena.vn"
GAME_ID = "1137"
SDK_KEY = "4dfd535a3a2ef92644301c3e3ce87c9f"
CHANNEL_ID = "10"
VERSION = "5.36.007"
PATH = "/v2/auth/login"
UA = "GCloudSDK/1.0"


def safe(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"))


def md5hex(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def login(garena_access_token, region="VN", lang="en", body_extra=None):
    ts = str(int(time.time()))
    query = "channelid=%s&gameid=%s&lang=%s&os=1&ts=%s&version=%s" % (
        CHANNEL_ID, GAME_ID, lang, ts, VERSION)
    body = {
        "channel_dis": "Garena",
        "scenes": 1,
        "scenes_version": 2,
        "region": region,
        "channel_info": {"token": garena_access_token},
    }
    if body_extra:
        body.update(body_extra)
    body_str = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    sig = md5hex(PATH + "?" + query + body_str + SDK_KEY)
    url = MSDK_URL + PATH + "?" + query + "&sig=" + sig
    req = urllib.request.Request(url, data=body_str.encode("utf-8"), method="POST", headers={
        "User-Agent": UA, "Content-Type": "application/json", "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, "transport_error: %s" % e


def main():
    data = json.load(open(GARENA_TOKEN, encoding="utf-8"))["response"]
    at = data["access_token"]
    safe("[*] Garena token uid=%s open_id=%s" % (data.get("uid"), data.get("open_id")))
    status, body = login(at)
    safe("[*] HTTP %s" % status)
    try:
        j = json.loads(body)
    except Exception:
        safe("[-] bad response: " + body[:500])
        return 1
    if j.get("ret") != 0:
        safe("[-] MSDK login failed: " + body[:500])
        return 1
    token = j.get("token")
    safe("[+] MSDK LOGIN OK")
    masked = {}
    for k, v in j.items():
        if isinstance(v, str) and len(v) > 14:
            masked[k] = v[:6] + "..." + v[-4:]
        else:
            masked[k] = v
    safe(json.dumps(masked, ensure_ascii=False, indent=1))
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({
            "msdk_url": MSDK_URL,
            "gameid": GAME_ID,
            "channelid": CHANNEL_ID,
            "garena_access_token": at,
            "response": j,
            "game_openid": j.get("openid"),
            "game_token": token,
            "uid": j.get("uid"),
        }, f, indent=1)
    try:
        os.chmod(OUT, 0o600)
    except Exception:
        pass
    safe("[+] saved -> captures/msdk_token.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
