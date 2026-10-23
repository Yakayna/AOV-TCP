# -*- coding: utf-8 -*-
"""Chi mo Chrome de giai captcha DataDome (luu cookie), khong can login game.
Chay: Refresh_Captcha.cmd  (hoac python tools/refresh_captcha.py)
"""
import os, subprocess, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
CREDS = os.path.join(ROOT, "captures", ".garena_creds")

def main():
    try:
        acc = input("Tai khoan Garena: ").strip()
        print("Nhap mat khau (hien tren man hinh):")
        pw = input("Mat khau Garena: ")
    except EOFError:
        print("Thieu thong tin (khong nhap duoc)."); return 1
    if not acc or not pw:
        print("Thieu thong tin."); return 1
    os.makedirs(os.path.join(ROOT, "captures"), exist_ok=True)
    open(CREDS, "w", encoding="utf-8").write(acc + "\n" + pw + "\n")
    print("=" * 62)
    print("Mot cua so CHROME se mo. HAY GIAI CAPTCHA (checkbox/slider).")
    print("Dung dong cua so Chrome. Cho toi da ~200 giay.")
    print("=" * 62)
    rc = subprocess.run([PY, os.path.join(ROOT, "tools", "garena_oauth_final.py")], cwd=ROOT).returncode
    print("Chrome xong (rc=%s)." % rc)
    print("Neu captcha da giai xong: chay LUQ_Login.cmd de login vao lobby.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
