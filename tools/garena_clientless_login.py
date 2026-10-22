"""GARENA CLIENTLESS LOGIN -- full login without the game client.

Verified live 2026-10-22 on Lien Quan Mobile VN 1.64.1.7.

Flow:
  1. GET  /api/prelogin?app_id=100054&account=<acc>&format=json&id=<ts>
         -> {"v1": <salt1>, "v2": <salt2>}
  2. password param:
         E     = MD5(password)                  (16 bytes)
         inner = SHA256(hex(E) + v1)            (32 bytes)
         key   = SHA256(hex(inner) + v2)        (32 bytes)
         pw    = AES-256-ECB(key, E, NoPadding).hex()
  3. GET  /api/login?...&password=<pw>&redirect_uri=gop100054://auth/&format=json&id=<ts>
         -> {"uid":..., "session_key":..., "redirect_uri":...}
         Set-Cookie: sso_key=...
  4. POST /oauth/token/grant (form):
         client_id=100054, response_type=code, redirect_uri=gop100054://auth/,
         format=json, id=<ts>, client_type=2, source=2
         Cookie: datadome=...; sso_key=...
         -> {"code": <auth code>, "open_id": ...}
  5. POST /oauth/token/exchange (form):
         grant_type=authorization_code, code, redirect_uri, source=2,
         client_id=100054, client_secret=<MSDK key>, device_id, login_scenario=
         -> access_token, refresh_token, open_id

DataDome note: prelogin is protected. Reuse the datadome cookie from a real Chrome
visit (captures/garena_browser_state.json). If it is missing/expired, run
  python tools/garena_oauth_final.py
once (headful), solve the captcha, and this tool works again.

usage:
  python tools/garena_clientless_login.py
  python tools/garena_clientless_login.py --account X --password-file f
"""
import asyncio
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_ID = "100054"
APP_KEY = "027709b12673a3e18de16bf9b85723a2d55e9bffd3364aea67f176e533f69515"
BASE = "https://100054.connect.garena.com"
REDIRECT = "gop100054://auth/"
CREDS = os.path.join(ROOT, "captures", ".garena_creds")
STATE = os.path.join(ROOT, "captures", "garena_browser_state.json")
TOKENS = os.path.join(ROOT, "captures", "garena_token.json")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"


def safe(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"))


def now_ms():
    return str(int(time.time() * 1000))


def device_id():
    p = os.path.join(ROOT, "captures", ".garena_device_id")
    if os.path.exists(p):
        v = open(p, encoding="utf-8").read().strip()
        if v:
            return v
    v = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    open(p, "w", encoding="utf-8").write(v)
    return v


def load_creds(account=None, password=None, password_file=None):
    if password_file:
        password = open(password_file, encoding="utf-8").read().strip()
    if account and password:
        return account, password
    with open(CREDS, "r", encoding="utf-8") as f:
        lines = [x.strip() for x in f.read().splitlines() if x.strip()]
    return account or lines[0], password or lines[1]


def datadome_cookie():
    try:
        st = json.load(open(STATE, encoding="utf-8"))
        for c in st.get("cookies", []):
            if c.get("name") == "datadome":
                return c.get("value", "")
    except Exception:
        pass
    return ""


def http(method, path, form=None, cookie="", headers=None):
    url = BASE + path
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    h = {"User-Agent": UA, "Accept": "application/json, text/plain, */*",
         "Referer": BASE + "/universal/oauth", "Origin": BASE}
    if cookie:
        h["Cookie"] = cookie
    if form is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), e.headers
    except Exception as e:
        return None, "transport_error: %s" % e, {}


def hmac_sha256_hex(key, msg):
    import hmac
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def encrypted_password(password, v1, v2):
    E = hashlib.md5(password.encode("utf-8")).digest()
    inner = hashlib.sha256(E.hex().encode() + v1.encode()).digest()
    key = hashlib.sha256(inner.hex().encode() + v2.encode()).digest()
    return aes256_ecb_hex(key, E)


def aes256_ecb_hex(key, data):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return (c.update(data) + c.finalize()).hex()
    except Exception:
        pass
    # openssl fallback
    import subprocess, tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        p = f.name
    try:
        out = subprocess.run(["openssl", "enc", "-aes-256-ecb", "-K", key.hex(), "-nopad", "-nosalt", "-in", p],
                             capture_output=True)
        if out.returncode == 0:
            return out.stdout.hex()
    finally:
        os.unlink(p)
    raise SystemExit("[!] need cryptography or openssl for AES")


def refresh_datadome():
    """Headless browser visit to obtain a fresh datadome cookie (no login)."""
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return ""
    chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

    async def go():
        async with async_playwright() as p:
            b = await p.chromium.launch(executable_path=chrome, headless=True,
                                        args=["--disable-blink-features=AutomationControlled", "--no-first-run"])
            ctx = await b.new_context(locale="vi-VN",
                                      user_agent=UA)
            page = await ctx.new_page()
            await page.goto(BASE + "/universal/oauth?redirect_uri=gop100054%3A%2F%2Fauth%2F&response_type=code&client_id=100054&locale=vi_VN",
                            wait_until="domcontentloaded", timeout=60000)
            await page.wait_for_timeout(6000)
            cookies = await ctx.cookies()
            await b.close()
            for c in cookies:
                if c.get("name") == "datadome":
                    return c.get("value", "")
            return ""
    try:
        return asyncio.run(go())
    except Exception:
        return ""


def main():
    account, password = load_creds()
    dd = datadome_cookie()
    if not dd:
        safe("[*] no datadome cookie, trying headless refresh")
        dd = refresh_datadome()
    if not dd:
        safe("[!] no datadome cookie. run: python tools/garena_oauth_final.py (headful, solve captcha)")
        return 2

    st, body, _ = http("GET", "/api/prelogin?app_id=%s&account=%s&format=json&id=%s" % (
        APP_ID, urllib.parse.quote(account), now_ms()), cookie="datadome=" + dd)
    if st != 200:
        safe("[!] prelogin HTTP %s (DataDome?). body: %s" % (st, body[:200]))
        safe("[!] run python tools/garena_oauth_final.py once to refresh the datadome cookie")
        return 2
    pre = json.loads(body)
    safe("[*] prelogin ok (v1=%s v2=%s)" % (pre.get("v1"), str(pre.get("v2"))[:6] + "..."))

    pw = encrypted_password(password, pre["v1"], pre["v2"])
    q = "/api/login?app_id=%s&account=%s&password=%s&redirect_uri=%s&format=json&id=%s" % (
        APP_ID, urllib.parse.quote(account), pw, urllib.parse.quote(REDIRECT, safe=""), now_ms())
    st, body, headers = http("GET", q, cookie="datadome=" + dd)
    if st != 200:
        safe("[!] login HTTP %s: %s" % (st, body[:300]))
        return 3
    lg = json.loads(body)
    safe("[*] login ok: uid=%s open_id will be fetched" % lg.get("uid"))

    jar = ["datadome=" + dd]
    for sc in (headers.get_all("Set-Cookie") or []):
        jar.append(sc.split(";")[0])
    cookie = "; ".join(jar)

    params = {
        "client_id": APP_ID, "response_type": "code", "redirect_uri": REDIRECT,
        "format": "json", "id": now_ms(), "client_type": "2", "source": "2",
    }
    st, body, _ = http("POST", "/oauth/token/grant", form=params, cookie=cookie)
    if st != 200 or "code" not in body:
        safe("[!] grant HTTP %s: %s" % (st, body[:400]))
        return 4
    gr = json.loads(body)
    safe("[*] grant ok: open_id=%s" % gr.get("open_id"))

    ex = {
        "grant_type": "authorization_code", "code": gr["code"], "redirect_uri": REDIRECT,
        "source": "2", "client_id": APP_ID, "client_secret": APP_KEY,
        "device_id": device_id(), "login_scenario": "",
    }
    st, body, _ = http("POST", "/oauth/token/exchange", form=ex, cookie="datadome=" + dd)
    if st != 200:
        safe("[!] exchange HTTP %s: %s" % (st, body[:400]))
        return 5
    tok = json.loads(body)
    if not tok.get("access_token"):
        safe("[!] exchange error: %s" % body[:400])
        return 5

    masked = {k: (v[:6] + "..." + v[-4:] if isinstance(v, str) and len(v) > 14 else v) for k, v in tok.items()}
    safe("[+] LOGIN CLIENTLESS OK")
    safe(json.dumps(masked, ensure_ascii=True, indent=1))
    with open(TOKENS, "w", encoding="utf-8") as f:
        json.dump({"app_id": APP_ID, "account": account, "device_id": device_id(),
                   "uid": tok.get("uid"), "open_id": tok.get("open_id"), "response": tok}, f, indent=1)
    try:
        os.chmod(TOKENS, 0o600)
    except Exception:
        pass
    safe("[+] saved -> captures/garena_token.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
