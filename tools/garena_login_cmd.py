# -*- coding: utf-8 -*-
"""
LOGIN GARENA + LOBBY (clientless) — nhập tài khoản/mật khẩu Garena trong CMD.
Không cần mở game client.

Quy trình:
  1) Nhập account/password Garena (hoặc truyền --account/--password).
  2) Garena OAuth clientless (username/password -> access_token).
     - Nếu DataDome hết hạn: tự mở Chrome (Playwright) để lấy cookie mới
       rồi thử lại (DataDome thường tự pass với Chrome thật).
  3) MSDK login (Garena token -> game token/openid).
  4) Gateway clientless login + nhận lobby 0x4013 + giữ phiên (treo).

Chạy:
  python tools/garena_login_cmd.py
  python tools/garena_login_cmd.py --account X --password Y
  python tools/garena_login_cmd.py --hold-seconds 15   (test tự dừng)
"""
import argparse, getpass, json, os, subprocess, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
CREDS = os.path.join(ROOT, "captures", ".garena_creds")
GTOKEN = os.path.join(ROOT, "captures", "garena_token.json")
MTOKEN = os.path.join(ROOT, "captures", "msdk_token.json")
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)

def run(script, timeout=180, extra=None):
    cmd = [PY, os.path.join(ROOT, "tools", script)] + (extra or [])
    log("RUN %s" % script)
    try:
        p = subprocess.run(cmd, cwd=ROOT, timeout=timeout)
        return p.returncode
    except subprocess.TimeoutExpired:
        log("TIMEOUT %s" % script); return -1

def write_creds(acc, pw):
    with open(CREDS, "w", encoding="utf-8") as f:
        f.write(acc + "\n" + pw + "\n")
    try: os.chmod(CREDS, 0o600)
    except Exception: pass

def garena_login(acc, pw):
    write_creds(acc, pw)
    rc = run("garena_clientless_login.py", timeout=120)
    if rc == 0:
        log("GARENA LOGIN OK (clientless)"); return True
    log("Garena clientless thất bại (rc=%s) — DataDome cần cookie mới, mở Chrome..." % rc)
    log(">>> Nếu Chrome hiện captcha, hãy giải trực tiếp trong cửa sổ Chrome (chỉ 1 lần).")
    rc2 = run("garena_oauth_final.py", timeout=300)
    log("Chrome OAuth xong (rc=%s) — thử lại clientless..." % rc2)
    rc3 = run("garena_clientless_login.py", timeout=120)
    if rc3 == 0:
        log("GARENA LOGIN OK (sau khi refresh cookie)"); return True
    log("GARENA LOGIN THẤT BẠI (kiểm tra mk/captcha rồi chạy lại)"); return False

ITOP_OUT = os.path.join(ROOT, "captures", "itop_built_login_live.json")

def msdk_login():
    # Dùng /v2/auth/login định dạng GIỐNG APP (có device_info) để token game được server tin
    rc = run("itop_codec.py", timeout=180,
             extra=["build-login", "--live", "--out", "captures/itop_built_login_live.json"])
    if rc == 0:
        try:
            j = json.load(open(ITOP_OUT, encoding="utf-8"))
            p = (j.get("response") or {}).get("plaintext") or {}
            if p.get("token"):
                out = {"response": {"ret": p.get("ret", 0), "msg": p.get("msg", "success"),
                                    "openid": p.get("openid"), "channel_id": p.get("channel_id", 10),
                                    "uid": p.get("uid"), "token": p.get("token"),
                                    "token_expire_time": p.get("token_expire_time"),
                                    "user_name": p.get("user_name"), "pf": p.get("pf"),
                                    "pf_key": p.get("pf_key"), "first": p.get("first"),
                                    "channel_info": p.get("channel_info")}}
                json.dump(out, open(MTOKEN, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
                log("MSDK OK (app-like) | openid=%s | token=%s... | first=%s" % (
                    p.get("openid"), str(p.get("token"))[:12], p.get("first")))
                return True
        except Exception as e:
            log("itop build-login lỗi đọc kết quả: %s" % e)
    log("Thử fallback msdk_login.py ...")
    rc = run("msdk_login.py", timeout=120)
    if rc != 0:
        log("MSDK LOGIN THẤT BẠI (rc=%s)" % rc); return False
    try:
        d = json.load(open(MTOKEN, encoding="utf-8"))["response"]
        log("MSDK OK (fallback) | openid=%s | token=%s..." % (d.get("openid"), str(d.get("token",""))[:12]))
        return True
    except Exception as e:
        log("MSDK token file lỗi: %s" % e); return False

def read_password_interactive():
    # input() hiển thị để hỗ trợ dán (Ctrl+V) — getpass trên Windows có thể chỉ nhận 1 ký tự khi dán.
    print("Mật khẩu Garena (gõ hoặc dán, sẽ hiện trên màn hình): ", end="", flush=True)
    return input()

def write_creds_verified(acc, pw):
    write_creds(acc, pw)
    # verify file
    lines = [x.rstrip("\r") for x in open(CREDS, "r", encoding="utf-8").read().split("\n")]
    got_acc = lines[0].strip() if len(lines) > 0 else ""
    got_pw = lines[1] if len(lines) > 1 else ""
    ok = (got_acc == acc and got_pw == pw)
    log("CREDS %s | account=%s | password length=%d" % ("OK" if ok else "MISMATCH", acc, len(pw)))
    return ok

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--account", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--password-file", default=None)
    ap.add_argument("--hold-seconds", type=int, default=None)
    ap.add_argument("--check-creds", action="store_true")
    args = ap.parse_args()
    log("=" * 64)
    log("LIÊN QUÂN MOBILE — LOGIN GARENA + LOBBY CLIENTLESS (CMD)")
    log("Không cần mở game client. Acc cũ bị ban: dùng acc khác.")
    log("=" * 64)
    acc = (args.account or "").strip()
    if not acc:
        acc = input("Tài khoản Garena: ").strip()
    pw = args.password
    if pw is None and args.password_file:
        p = args.password_file
        if not os.path.isabs(p): p = os.path.join(ROOT, p)
        try:
            raw = open(p, "r", encoding="utf-8", errors="replace").read()
            os.remove(p)
        except Exception as e:
            log("Không đọc được password-file: %s" % e); return 1
        pw = raw.replace("\r\n", "\n").rstrip("\n")
    if pw is None:
        pw = read_password_interactive()
    if not acc or not pw:
        log("Thiếu tài khoản/mật khẩu."); return 1
    if len(pw) <= 1:
        log("CẢNH BÁO: mật khẩu chỉ có %d ký tự — có thể bạn dán bằng Ctrl+V bị lỗi." % len(pw))
        if not args.check_creds:
            pw2 = read_password_interactive()
            if pw2: pw = pw2
    if not write_creds_verified(acc, pw):
        log("Ghi creds thất bại."); return 1
    if args.check_creds:
        log("CHECK-CREDS OK — file captures/.garena_creds đã đúng."); return 0
    if not garena_login(acc, pw): return 1
    if not msdk_login(): return 1
    try:
        _tok = json.load(open(MTOKEN, encoding="utf-8"))["response"]
        log("LƯU Ý: nếu gateway trả S-Stop 0x11/0x08, token/acc có thể chưa được world tin hoặc bị hạn chế.")
    except Exception: pass
    log("VÀO LOBBY CLIENTLESS — cửa sổ sẽ treo (Ctrl+C để dừng)...")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import lobby_hold
    try:
        lobby_hold.run_hold(args.hold_seconds)
    except KeyboardInterrupt:
        log("Đã dừng theo Ctrl+C")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
