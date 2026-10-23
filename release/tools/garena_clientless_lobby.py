# -*- coding: utf-8 -*-
"""FULL CLIENTLESS PIPELINE: Garena username/password -> lobby (no game client).

Steps:
  1) Garena clientless login (username/password -> access_token). DataDome may require
     a one-time Chrome refresh (tools/garena_oauth_final.py) - handled automatically.
  2) MSDK app-like login (itop /v2/auth/login) -> MSDK game token.
  3) 16-bit auth tail: cached in captures/token_tails.json or brute-forced (~1-3 min).
  4) Replay captured first-login frame template (patched for this account) against
     candidate gateways -> server creates world session and pushes lobby 0x4013.

Usage:
  python tools/garena_clientless_lobby.py --account X --password Y
  python tools/garena_clientless_lobby.py            # prompts
"""
import argparse, getpass, json, os, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
CREDS = os.path.join(ROOT, "captures", ".garena_creds")
GTOKEN = os.path.join(ROOT, "captures", "garena_token.json")
MTOKEN = os.path.join(ROOT, "captures", "msdk_token.json")
TAILS = os.path.join(ROOT, "captures", "token_tails.json")
ITOP_OUT = os.path.join(ROOT, "captures", "trust", "msdk_pipeline.json")
LOG = os.path.join(ROOT, "captures", "trust", "pipeline_log.json")


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def run(script, extra=None, timeout=300):
    cmd = [PY, os.path.join(ROOT, "tools", script)] + (extra or [])
    log("RUN %s %s" % (script, " ".join(extra or [])))
    try:
        p = subprocess.run(cmd, cwd=ROOT, timeout=timeout)
        return p.returncode
    except subprocess.TimeoutExpired:
        log("TIMEOUT %s" % script)
        return -1


def write_creds(acc, pw):
    with open(CREDS, "w", encoding="utf-8") as f:
        f.write(acc + "\n" + pw + "\n")
    try: os.chmod(CREDS, 0o600)
    except Exception: pass


def garena_login(acc, pw):
    write_creds(acc, pw)
    rc = run("garena_clientless_login.py", timeout=150)
    if rc != 0:
        log("=" * 62)
        log("DataDome chan login. Mot cua so CHROME se mo ra.")
        log(">>> HAY GIAI CAPTCHA (checkbox/slider) TRONG CUA SO CHROME <<<")
        log(">>> Dung dong cua so Chrome. Cho toi da ~200 giay. <<<")
        log("=" * 62)
        run("garena_oauth_final.py", timeout=320)
        log("Da thu xong Chrome, dang thu lai login clientless...")
        rc = run("garena_clientless_login.py", timeout=150)
    if rc != 0:
        return None
    try:
        g = json.load(open(GTOKEN, encoding="utf-8"))
        return g
    except Exception as e:
        log("read garena token fail: %s" % e); return None


def mint_msdk(g):
    access = g["response"]["access_token"]
    oid = g.get("open_id") or g["response"].get("open_id")
    rc = run("itop_codec.py", ["build-login", "--live", "--token", access, "--uid", str(oid),
                               "--out", os.path.relpath(ITOP_OUT, ROOT)], timeout=180)
    if rc != 0:
        return None
    try:
        j = json.load(open(ITOP_OUT, encoding="utf-8"))
        p = (j.get("response") or {}).get("plaintext") or {}
        if not p.get("token"): return None
        out = {"response": {"ret": p.get("ret", 0), "msg": p.get("msg", "success"),
                            "openid": p.get("openid"), "channel_id": p.get("channel_id", 10),
                            "uid": p.get("uid"), "token": p.get("token"),
                            "token_expire_time": p.get("token_expire_time"),
                            "user_name": p.get("user_name"), "pf": p.get("pf"),
                            "pf_key": p.get("pf_key"), "first": p.get("first"),
                            "channel_info": p.get("channel_info")}}
        json.dump(out, open(MTOKEN, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        return out["response"]
    except Exception as e:
        log("parse itop response fail: %s" % e); return None


def ensure_tail(token):
    try:
        tails = json.load(open(TAILS, encoding="utf-8"))
    except Exception:
        tails = {}
    if token in tails:
        return tails[token]
    rc = run("brute_tail.py", timeout=480)
    try:
        tails = json.load(open(TAILS, encoding="utf-8"))
    except Exception:
        return None
    return tails.get(token)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--account", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--cached-garena-xml", default=None, help="use a cached com.garena.msdk.token_cache.xml instead of username/password")
    ap.add_argument("--cached-garena-json", default=None, help="use a saved garena_token.json instead of username/password")
    ap.add_argument("--refresh-captcha", action="store_true", help="only refresh DataDome cookie via Chrome, then exit")
    args = ap.parse_args()
    try:
        acc = (args.account or "").strip() or input("Tai khoan Garena: ").strip()
        if args.password:
            pw = args.password
        else:
            print("Nhap mat khau (se hien tren man hinh de tranh loi dan Ctrl+V):")
            pw = input("Mat khau Garena: ")
    except EOFError:
        print("Thieu thong tin (khong nhap duoc)."); return 1
    if not acc or not pw:
        log("missing credentials"); return 1
    log("=" * 60); log("GARENA -> MSDK -> CLIENTLESS LOBBY"); log("=" * 60)
    os.makedirs(os.path.join(ROOT, "captures", "trust"), exist_ok=True)
    g = None
    if args.cached_garena_json:
        try:
            g = json.load(open(args.cached_garena_json, encoding="utf-8"))
            log("using cached garena_token.json")
        except Exception as e:
            log("cached garena json fail: %s" % e)
    elif args.cached_garena_xml:
        try:
            import html as _html
            xml = _html.unescape(open(args.cached_garena_xml, encoding="utf-8").read())
            j = json.loads(xml[xml.find("{"): xml.rfind("}") + 1])
            g = {"account": acc, "open_id": j.get("openId"),
                 "response": {"access_token": j.get("authToken"), "open_id": j.get("openId"),
                              "expiry_time": j.get("expiryTimestamp"),
                              "refresh_token": j.get("refreshToken")}}
            log("using cached Garena token from %s" % args.cached_garena_xml)
        except Exception as e:
            log("cached garena xml fail: %s" % e)
    if not g:
        g = garena_login(acc, pw)
    if not g:
        log("GARENA LOGIN FAILED"); return 1
    log("GARENA OK | account=%s | open_id=%s" % (g.get("account"), g.get("open_id")))
    tok = mint_msdk(g)
    if not tok:
        log("MSDK MINT FAILED"); return 1
    log("MSDK OK | openid=%s | token=%s..." % (tok.get("openid"), str(tok.get("token"))[:12]))
    tail = ensure_tail(tok["token"])
    if tail is None:
        log("TAIL FAILED (brute found nothing)"); return 1
    log("TAIL OK | %s" % tail)
    rc = run("clientless_lobby_replay.py", ["--token-json", os.path.relpath(MTOKEN, ROOT),
                                            "--openid-hex", str(g.get("open_id") or "")], timeout=300)
    result = {"account": acc, "open_id": g.get("open_id"), "openid": tok.get("openid"),
              "token_head": str(tok.get("token"))[:12], "tail": tail,
              "replay_rc": rc, "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        ev = json.load(open(os.path.join(ROOT, "captures", "lobby_session_evidence.json"), encoding="utf-8"))
        result["success"] = bool(ev.get("success"))
        result["gateway"] = ev.get("gateway")
        result["server_frames"] = (ev.get("result") or {}).get("server_frames")
        result["big"] = (ev.get("result") or {}).get("big")
        result["hits"] = (ev.get("result") or {}).get("hits")
    except Exception:
        result["success"] = (rc == 0)
    json.dump(result, open(LOG, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    log("RESULT: %s" % json.dumps(result, ensure_ascii=False))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
