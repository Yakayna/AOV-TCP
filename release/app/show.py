# -*- coding: utf-8 -*-
"""Giao dien gon gang de chay/record: khong in chi tiet ky thuat ra man hinh."""
import argparse, json, os, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
CAP = os.path.join(ROOT, "captures")
LOG_DIR = os.path.join(ROOT, "app", "logs")
PY = sys.executable
sys.path.insert(0, TOOLS)
import hold_lobby  # noqa: E402

LOG_PATH = ""


def log_file():
    global LOG_PATH
    if not LOG_PATH:
        os.makedirs(LOG_DIR, exist_ok=True)
        LOG_PATH = os.path.join(LOG_DIR, "latest.log")
        open(LOG_PATH, "w", encoding="utf-8").close()
    return LOG_PATH


def append_log(text):
    try:
        with open(log_file(), "a", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass


def step(msg):
    print(msg, flush=True)


def run_hidden(script, extra=None, timeout=600):
    cmd = [PY, "-u", os.path.join(TOOLS, script)] + (extra or [])
    append_log("\n$ " + " ".join(cmd) + "\n")
    try:
        p = subprocess.run(cmd, cwd=ROOT, timeout=timeout, capture_output=True, text=True, encoding="utf-8", errors="replace")
        append_log((p.stdout or "") + (p.stderr or ""))
        return p.returncode
    except subprocess.TimeoutExpired as e:
        append_log("TIMEOUT %s" % script)
        return -1
    except Exception as e:
        append_log("ERR %s: %s" % (script, e))
        return -1


def read_password(prompt):
    """Masked password input that supports paste; fallback to visible if empty."""
    print(prompt, end="", flush=True)
    chars = []
    try:
        import msvcrt
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                print()
                if not chars:
                    print("  (Khong nhan duoc ky tu - nhap lai, mat khau se hien)")
                    return input("  Mat khau Garena  : ")
                return "".join(chars)
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch == "\x08":
                if chars:
                    chars.pop()
                    print("\b \b", end="", flush=True)
                continue
            if ch == "\x00" or ch == "\xe0":
                msvcrt.getwch()
                continue
            if ch.isprintable():
                chars.append(ch)
                print("*", end="", flush=True)
    except ImportError:
        return input()
    except EOFError:
        return "".join(chars)


def banner():
    os.system("cls")
    print("============================================================")
    print("            LIEN QUAN MOBILE  -  DANG NHAP TU DONG")
    print("============================================================")
    print()


def save_creds(acc, pw):
    os.makedirs(CAP, exist_ok=True)
    with open(os.path.join(CAP, ".garena_creds"), "w", encoding="utf-8") as f:
        f.write(acc + "\n" + pw + "\n")


def do_login(acc, pw):
    step("[1/4] Dang ket noi Garena...")
    rc = run_hidden("garena_clientless_login.py", timeout=150)
    if rc != 0:
        step("      Can xac minh captcha. Mot cua so Chrome se mo ra.")
        step("      >>> Hay giai captcha trong cua so Chrome (khong dong cua so). <<<")
        run_hidden("garena_oauth_final.py", timeout=320)
        step("      Dang thu lai...")
        rc = run_hidden("garena_clientless_login.py", timeout=150)
    if rc != 0:
        return None
    try:
        return json.load(open(os.path.join(CAP, "garena_token.json"), encoding="utf-8"))
    except Exception:
        return None


def do_mint(g):
    step("[2/4] Dang chuan bi phien game...")
    access = g["response"]["access_token"]
    oid = g.get("open_id") or g["response"].get("open_id")
    rc = run_hidden("itop_codec.py", ["build-login", "--live", "--token", access, "--uid", str(oid),
                                      "--out", os.path.join("captures", "trust", "msdk_pipeline.json")], timeout=180)
    if rc != 0:
        return None
    try:
        j = json.load(open(os.path.join(CAP, "trust", "msdk_pipeline.json"), encoding="utf-8"))
        p = (j.get("response") or {}).get("plaintext") or {}
        tok = {"response": {"ret": 0, "msg": "success", "openid": p.get("openid"), "channel_id": 10,
                            "uid": p.get("uid"), "token": p.get("token"),
                            "token_expire_time": p.get("token_expire_time"), "user_name": p.get("user_name"),
                            "pf": p.get("pf"), "pf_key": p.get("pf_key"), "first": p.get("first"),
                            "channel_info": p.get("channel_info")}}
        json.dump(tok, open(os.path.join(CAP, "msdk_token.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        return tok["response"]
    except Exception:
        return None


def do_tail(token):
    step("[3/4] Dang xac thuc phien (1-4 phut)...")
    tails = {}
    try:
        tails = json.load(open(os.path.join(CAP, "token_tails.json"), encoding="utf-8"))
    except Exception:
        pass
    if token not in tails:
        rc = run_hidden("brute_tail.py", timeout=480)
        try:
            tails = json.load(open(os.path.join(CAP, "token_tails.json"), encoding="utf-8"))
        except Exception:
            return None
    return tails.get(token)


def do_enter(tok):
    step("[4/4] Dang ket noi vao sanh...")
    rc = run_hidden("clientless_lobby_replay.py", ["--token-json", os.path.join("captures", "msdk_token.json"),
                                                   "--openid-hex", str(tok.get("uid") or "")], timeout=280)
    if rc != 0:
        return False
    try:
        ev = json.load(open(os.path.join(CAP, "lobby_session_evidence.json"), encoding="utf-8"))
        return bool(ev.get("success"))
    except Exception:
        return False


def quiet_create(ses):
    rc = run_hidden("clientless_lobby_replay.py", ["--token-json", os.path.join("captures", "msdk_token.json"),
                                                   "--openid-hex", str(ses.get("openid_hex") or "")], timeout=360)
    if rc != 0:
        return False
    try:
        ev = json.load(open(os.path.join(CAP, "lobby_session_evidence.json"), encoding="utf-8"))
        return bool(ev.get("success"))
    except Exception:
        return False


def hold_forever(tok, cycles=None):
    ses = hold_lobby.load_session()
    if not ses:
        return False
    step("=" * 60)
    step("  DA VAO SANH. Dang duy tri ket noi 24/7.")
    step("  Giu cua so nay mo. Ctrl+C de dung.")
    step("=" * 60)
    started = time.time()
    fails = 0
    n = 0
    while True:
        ok = False
        for ip, port in hold_lobby.GATEWAYS:
            r = hold_lobby.ping_gateway(ses, ip, port)
            if r and r.get("auth") and r.get("big", 0) > 0:
                ok = True
                break
        if not ok:
            append_log("hold: session offline -> recreate\n")
            ok = quiet_create(ses)
        mins = int((time.time() - started) // 60)
        if ok:
            fails = 0
            print("  ONLINE  |  dang duy tri ket noi  (%d phut)" % mins, flush=True)
        else:
            fails += 1
            print("  Dang thu ket noi lai...  (%d)" % mins, flush=True)
        if cycles is not None:
            n += 1
            if n >= cycles:
                return True
        time.sleep(hold_lobby.PING_INTERVAL if ok else hold_lobby.RETRY_INTERVAL)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--account", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--skip-login", action="store_true", help="use saved token (only for testing UI)")
    ap.add_argument("--hold-cycles", type=int, default=None)
    args = ap.parse_args()
    banner()
    if args.skip_login:
        try:
            tok = json.load(open(os.path.join(CAP, "msdk_token.json"), encoding="utf-8"))["response"]
        except Exception:
            step("Khong co phien da luu.")
            return 1
        hold_forever(tok, args.hold_cycles)
        return 0
    acc = args.account or input("  Tai khoan Garena : ").strip()
    pw = args.password or read_password("  Mat khau Garena  : ")
    if not acc or not pw:
        step("  Thieu thong tin.")
        return 1
    save_creds(acc, pw)
    g = do_login(acc, pw)
    if not g:
        step("  Khong dang nhap duoc. Kiem tra lai tai khoan/mat khau hoac captcha.")
        return 1
    tok = do_mint(g)
    if not tok:
        step("  Khong tao duoc phien game. Thu lai sau.")
        return 1
    tail = do_tail(tok["token"])
    if not tail:
        step("  Xac thuc phien that bai. Thu lai sau.")
        return 1
    if not do_enter(tok):
        step("  Chua vao duoc sanh. Dang thu lai...")
        time.sleep(5)
        if not do_enter(tok):
            step("  Khong vao duoc sanh. Chi tiet trong app/logs/latest.log")
            return 1
    print("  Xin chao %s!" % (tok.get("user_name") or acc))
    hold_forever(tok, args.hold_cycles)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n  Da dung.")
    except Exception:
        print("  Co loi xay ra. Chi tiet trong app/logs/latest.log")
