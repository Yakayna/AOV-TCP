# AOV / Liên Quân Mobile — clientless toolkit (VN 1.64.1.7)

Bộ tool **reverse-engineering** để thử đăng nhập Liên Quân Mobile (Garena VN, package
`com.garena.game.kgvn` 1.64.1.7) **không cần game client** — chỉ dùng tài khoản Garena
qua các giao thức TCP/HTTP mà mình đã reverse được.

> ⚠️ Đây là repo nghiên cứu/học thuật. **Không có token, tài khoản, cookie hay dữ liệu
> người chơi nào trong repo.** Tự chuẩn bị đầu vào của bạn (xem bên dưới).
> Việc dùng tool có thể vi phạm điều khoản của Garena; tự chịu trách nhiệm.
> Đừng dùng cho rank/competitive.

---

## Đang làm được gì (verified)

| Bước | Trạng thái |
|---|---|
| Đăng nhập Garena bằng **username/password** (clientless HTTP: prelogin → api/login → oauth grant → token exchange) | ✅ chạy được (cần cookie DataDome hoặc refresh bằng Chrome thật 1 lần) |
| Mint **MSDK game token** đúng format app (`/v2/auth/login`, encrypt=1, device_info đầy đủ) | ✅ chạy được |
| Dò **tail IV-struct 16-bit** cho token mới (protocol TSF4G yêu cầu) | ✅ ~1–3 phút/token, có cache |
| Realm 6670: auth token → gửi device reports → nhận **assignment IP:port** | ✅ |
| Gateway 6629/6630: `0x1001` → key; `0x2001` → `0x2002` + `0x6002` + `0x4013` hello | ✅ |
| `0x2001` **byte-identical với app** (plaintext 64B: 38 ký tự token + đệm + `0x17` + `tsf4g` + `0x07`) | ✅ mới xác minh 04/11 — dùng `release/src/aov/` |
| Gửi `f0` device report → nhận dữ liệu lobby `0x4013` | ⚠️ chỉ với token **đã từng được game client đăng nhập** (server-side trust) |
| World-login/lobby với token mint hoàn toàn clientless | ❌ server trả `S-Stop 0x11` (chưa trust) |

> 📌 **Xác minh mới 04/11/2026:** layout `0x2001` đã khớp app từng byte (64B: `token[2:40]` + đệm + `0x17` + `tsf4g` + `0x07`), HEAD/tail khớp IV của app, không có MAC trong frame, và gate lobby không nằm trong `libgcloud.so`. Chi tiết: [`release/docs/VERIFIED_2026-11-04.md`](release/docs/VERIFIED_2026-11-04.md). Package mới `release/src/aov/` (crypto + frame + login + brute_tail) có self-test: `python release/tests/test_crypto.py`.

**Blocker hiện tại:** game server quyết định “trust” token ở phía server, không có bước
nào trong code client để copy thêm (đã đào IL2CPP + libgcloud). Hướng giải quyết:
capture **first-login của acc mới qua app** rồi replay để tìm trường được server bind
(xem mục “Hướng tiếp theo”).

---

## Yêu cầu để login

1. **Python 3.10+** và `pip install -r requirements.txt` (cryptography).
2. **Tài khoản Garena hợp lệ** (tên đăng nhập + mật khẩu). Repo KHÔNG kèm tài khoản.
3. **Cookie DataDome** (chống bot của Garena):
   - Nếu chưa có: chạy `python tools/garena_oauth_final.py` (cần Chrome + playwright)
     để đăng nhập bằng trình duyệt thật 1 lần và lưu `captures/garena_browser_state.json`.
   - Cookie này thuộc về bạn; **không commit** (đã nằm trong .gitignore).
4. **Device fingerprint** cho MSDK login kiểu app:
   - Copy profile của bạn vào biến môi trường `AOV_DEVICE_UUID` (mặc định là uuid rỗng).
5. **Pcap phiên app của chính bạn** (1 lần) để sinh template:
   - Bật app, đăng nhập 1 acc, bắt TCP 6670/6629/6630 bằng tcpdump.
   - `python tools/make_frameset.py captures/app_login.pcap`
     → tạo `captures/connect_6670_frameset.json` (0x1001 + 0x2001 header, **không token**).
   - `python tools/save_realm_templates.py captures/app_login.pcap`
     → tạo `captures/realm_templates.json` (device reports cho realm).
   - `python tools/make_f0_payload.py captures/app_login.pcap`
     → tạo `captures/f0_payload.bin` (device report f0).
6. **Token game**: tool tự mint từ tài khoản Garena của bạn. Không dùng token người khác.

---

## Cách chạy

```
pip install -r requirements.txt

# 1) (mot lan) tao template tu pcap cua ban
python tools/make_frameset.py captures/app_login.pcap
python tools/save_realm_templates.py captures/app_login.pcap
python tools/make_f0_payload.py captures/app_login.pcap

# 2) (neu chua co cookie DataDome) refresh bang Chrome
python tools/garena_oauth_final.py

# 3) login + thu vao lobby (nhap acc/mk trong CMD)
python tools/garena_login_cmd.py
```

`garena_login_cmd.py` sẽ: Garena login → mint MSDK token (app-like) → dò tail nếu
chưa có → realm assignment → gateway auth → gửi reports/f0 → giữ phiên.
Nếu server trả `S-Stop 0x11` nghĩa là token chưa được world trust (đúng như giới hạn
ở trên).

Các tool lẻ:
- `tools/garena_clientless_login.py` — Garena username/password → access token.
- `tools/itop_codec.py build-login --live` — mint MSDK token app-like.
- `tools/brute_tail.py` — dò tail IV chưa biết cho token hiện tại.
- `tools/lobby_hold.py` — realm → gateway → reports → giữ phiên.

---

## Cấu trúc

```
tools/            # Python tools (khong chua secret)
docs/PROTOCOL.md  # tom tat giao thuc da reverse
captures/         # INPUT cua ban (gitignored): token, cookie, pcap, templates
```

---

## Hướng tiếp theo (đang làm)

1. Capture **first-login acc mới** qua app (một lần) + logcat/Frida.
2. Replay y nguyên stream client bằng đúng token đó → xác nhận replay được lobby.
3. So sánh token app-mint vs tool-mint, tìm field server dùng để bind “trust”.
4. Nếu tìm ra → clientless 100% cho mọi acc; nếu không → tự động hoá “1 lần app login”
   cho mỗi acc mới.

Chi tiết giao thức: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Release: clientless lobby runner (khong can game client)

Thu muc `release/` chua ban chay san:

- `setup.cmd` - cai dependencies (playwright, cryptography)
- `Start.cmd` - nhap tai khoan/mat khau Garena, giai captcha neu co, vao sanh va giu online 24/7
- `HUONG_DAN.txt` - huong dan chi tiet
- `app/`, `tools/`, `captures/` - ma nguon va du lieu can thiet

Yeu cau: Windows + Python 3.10+ + Google Chrome + Internet.
