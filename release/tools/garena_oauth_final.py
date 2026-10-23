"""GARENA OAUTH FINAL -- login in real Chrome, then use the session cookie to get code and exchange token."""
import asyncio
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDS = os.path.join(ROOT, "captures", ".garena_creds")
APP_ID = "100054"
APP_KEY = "027709b12673a3e18de16bf9b85723a2d55e9bffd3364aea67f176e533f69515"
OAUTH_URL = ("https://100054.connect.garena.com/universal/oauth"
             "?redirect_uri=gop100054%3A%2F%2Fauth%2F&response_type=code"
             "&client_id=100054&locale=vi_VN")
REDIRECT = "gop100054://auth/"
EXCHANGE = "https://100054.connect.garena.com/oauth/token/exchange"
UA = "GarenaMSDK/4.0.39(V2218A ;Android 9;en;US;)"


def safe(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"))


def read_creds():
    with open(CREDS, "r", encoding="utf-8") as f:
        lines = [x.strip() for x in f.read().splitlines() if x.strip()]
    return lines[0], lines[1]


def device_id():
    p = os.path.join(ROOT, "captures", ".garena_device_id")
    if os.path.exists(p):
        v = open(p, encoding="utf-8").read().strip()
        if v:
            return v
    import uuid
    v = uuid.uuid4().hex
    open(p, "w", encoding="utf-8").write(v)
    return v


def post_form(url, fields):
    data = urllib.parse.urlencode({k: v for k, v in fields.items() if v is not None}).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, "transport_error: %s" % e


async def main():
    from playwright.async_api import async_playwright
    account, password = read_creds()
    safe("[*] account: " + account[:4] + "***" + account[-2:])
    state = {"login": None, "code": None, "redirect": None, "cookies": [], "follow": {}}
    ev = asyncio.Event()

    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=CHROME, headless=False,
                                          args=["--disable-blink-features=AutomationControlled", "--no-first-run"])
        ctx = await browser.new_context(viewport={"width": 1280, "height": 900}, locale="vi-VN")
        await ctx.add_init_script("""
          Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
          window.chrome = window.chrome || {runtime: {}};
          Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
        """)
        page = await ctx.new_page()
        netlog = []

        async def on_resp(resp):
            try:
                u = resp.url
                if "/api/" not in u and "oauth/" not in u:
                    return
                body = ""
                try:
                    body = (await resp.text())[:3000]
                except Exception:
                    pass
                netlog.append({"url": u[:300], "status": resp.status, "body": body})
                if "/api/login?" in u and resp.status == 200:
                    try:
                        state["login"] = json.loads(body)
                        safe("[+] LOGIN OK: uid=%s session_key=%s..." % (
                            state["login"].get("uid"), str(state["login"].get("session_key"))[:16]))
                        ev.set()
                    except Exception:
                        pass
                if "/api/prelogin" in u and resp.status == 403:
                    safe("[!] DataDome captcha -> SOLVE IT IN THE CHROME WINDOW (waiting)")
                m = re.search(r"[?&]code=([^&]+)", u)
                if m and "gop100054" in u and not state["code"]:
                    state["code"] = m.group(1)
                    state["redirect"] = u
                    safe("[+] code captured: " + u[:160].encode("ascii", "replace").decode())
                    ev.set()
            except Exception:
                pass
        page.on("response", lambda r: asyncio.create_task(on_resp(r)))

        async def on_req(r):
            u = r.url
            if u.startswith("gop100054://"):
                m = re.search(r"[?&]code=([^&]+)", u)
                if m and not state["code"]:
                    state["code"] = m.group(1)
                    state["redirect"] = u
                    ev.set()
        page.on("request", lambda r: asyncio.create_task(on_req(r)))

        await page.goto(OAUTH_URL, wait_until="domcontentloaded", timeout=60000)
        await page.wait_for_timeout(5000)
        await page.fill("input[type=text]", account)
        await page.fill("input[type=password]", password)
        safe("[*] submitting login")
        await page.click("button[type=submit]")

        try:
            await asyncio.wait_for(ev.wait(), timeout=200)
        except asyncio.TimeoutError:
            safe("[-] timeout waiting login/captcha")

        # follow-up: use session cookies to ask the OAuth API for the code
        if state["login"] and not state["code"]:
            await page.wait_for_timeout(2500)
            state["cookies"] = [{"name": c["name"], "domain": c["domain"]} for c in await ctx.cookies()]
            safe("[*] cookies: " + json.dumps(state["cookies"], ensure_ascii=True)[:600])
            paths = {
                "api_oauth": "/api/universal/oauth?" + "redirect_uri=gop100054%3A%2F%2Fauth%2F&response_type=code&client_id=100054&locale=vi-VN&format=json&id=" + str(int(__import__("time").time() * 1000)),
                "api_login": "/api/universal/login?" + "redirect_uri=gop100054%3A%2F%2Fauth%2F&response_type=code&client_id=100054&locale=vi-VN&format=json&id=" + str(int(__import__("time").time() * 1000)),
            }
            for name, path in paths.items():
                try:
                    res = await page.evaluate("""
                      async (path) => {
                        const r = await fetch(path, {credentials: 'include'});
                        const t = await r.text();
                        return {status: r.status, body: t.slice(0, 4000)};
                      }
                    """, path)
                    state["follow"][name] = res
                    safe("[*] %s -> %s %s" % (name, res.get("status"), str(res.get("body"))[:400]))
                    m = re.findall(r"code=([A-Za-z0-9_\-]{6,})", str(res.get("body", "")))
                    if m and not state["code"]:
                        state["code"] = m[0]
                except Exception as e:
                    safe("[!] follow %s failed: %s" % (name, e))
            if not state["code"]:
                sk = state["login"].get("session_key")
                if sk:
                    for endpoint in ["/oauth/token/exchange", "/oauth/token"]:
                        try:
                            res = await page.evaluate("""
                              async (args) => {
                                const r = await fetch(args[0], {method: 'POST', credentials: 'include',
                                  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                                  body: new URLSearchParams({grant_type:'authorization_code', code: args[1],
                                    redirect_uri:'gop100054://auth/', source:'2', client_id:'100054',
                                    client_secret: args[2], device_id: args[3]})});
                                return {status: r.status, body: (await r.text()).slice(0, 2000)};
                              }
                            """, [endpoint, sk, APP_KEY, device_id()])
                            state["follow"]["post_" + endpoint] = res
                            safe("[*] POST %s -> %s %s" % (endpoint, res.get("status"), str(res.get("body"))[:300]))
                        except Exception as e:
                            safe("[!] post %s failed: %s" % (endpoint, e))

        try:
            await ctx.storage_state(path=os.path.join(ROOT, "captures", "garena_browser_state.json"))
        except Exception:
            pass
        try:
            await page.screenshot(path=os.path.join(ROOT, "captures", "oauth_final.png"), full_page=True)
        except Exception:
            pass
        await asyncio.sleep(1)
        await browser.close()

    with open(os.path.join(ROOT, "captures", "oauth_flow_final.json"), "w", encoding="utf-8") as f:
        json.dump({"state": state, "net": netlog}, f, ensure_ascii=False, indent=1)
    safe("[*] saved captures/oauth_flow_final.json")

    code = state.get("code")
    if not code:
        safe("[-] no code found; check follow-up responses in oauth_flow_final.json")
        return 1
    safe("[+] exchanging code: " + code[:8] + "..." + code[-4:])
    status, body = post_form(EXCHANGE, {
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "source": "2", "client_id": APP_ID, "client_secret": APP_KEY,
        "device_id": device_id(), "login_scenario": "",
    })
    safe("[*] exchange HTTP %s" % status)
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = {"raw": body}
    if status == 200 and ("access_token" in parsed or "open_id" in parsed):
        safe("[+] TOKEN OK")
        masked = {k: (v[:6] + "..." + v[-4:] if isinstance(v, str) and len(v) > 14 else v) for k, v in parsed.items()}
        safe(json.dumps(masked, ensure_ascii=True, indent=1))
        with open(os.path.join(ROOT, "captures", "garena_token.json"), "w", encoding="utf-8") as f:
            json.dump({"app_id": APP_ID, "account": account, "device_id": device_id(), "response": parsed}, f, indent=1)
        safe("[+] saved captures/garena_token.json")
        return 0
    safe("[-] exchange failed: " + body[:800])
    return 1


raise SystemExit(asyncio.run(main()) or 0)
