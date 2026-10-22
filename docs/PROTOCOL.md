# Giao thức đã reverse (TSF4G / AOV VN 1.64.1.7)

## 1. TSF4G frame (TCP gateway 6629/6630, realm 6670)

```
magic   u16 BE  0x3366
headVer u16 BE  0x0008
bodyVer u16 BE  0x0008
cmd     u16 BE  (0x1001, 0x1002, 0x2001, 0x2002, 0x6002, 0x4013, 0x5001, 0x5002, ...)
flags   u32 LE  (0 = C→S, 1 = S→C)
seq     u32 LE
headLen u16 LE
??      u8      (0)
bodyLen u16 BE
??      u8      (extra, data-frame: 1)
body    ...
```
Header thường 21 byte; frame dữ liệu `0x4013` dùng 22 byte (byte 21 = 0x01 khi có).

## 2. Mã hoá body

- `0x1002` (SYN-ACK): 16-char ASCII session key nằm trong raw[23:39].
- `0x2001` auth request: `body = IV(16) || AES-128-CBC(key, IV, plaintext)`
  - plaintext = token_core(38 hex) + 19×0x00 + marker ngẫu nhiên + "tsf4g" + 0x07 (64 B)
  - IV = AES-128-ECB(key, AUTH_STRUCT)
  - AUTH_STRUCT = `fffe0207 35343530 08360b0b2547` + 2-byte tail
  - **tail phụ thuộc token** (16-bit, phải dò bruteforce 0–65535).
- `0x4013` data frame (C→S): IV = AES-128-ECB(key, STRUCT); STRUCT cố định theo loại
  frame, ví dụ f0 (seq 3): `000102009605060319090a1e8a0d0f0f`.
  - plaintext = payload + pad: `random bytes + "tsf4g" + padlen` cho đủ bội 16.
- `0x5002` S-Stop: body = `u32 BE code` + `u32 BE exCode`; 7 = close thường,
  8 = invalid struct (sai tail), 0x11 = reject chung / token chưa trust, 0x12 = invalid.

## 3. Flow realm (6670)

```
C 0x1001(syn)
S 0x1002(key)
C 0x2001(token + tail)
S 0x2002 + 0x6002 + 0x4013 (hello)
C 0x4013 seq3 (32B report) + seq4 (576B device blob) + seq5 (32B report)
S 0x4013 (assignment: [u32 len][IP cstring][u16 BE port]) + 0x5002 code 7
C 0x5001 (C-Stop)
```

## 4. Flow gateway (6629/6630)

```
C 0x1001 -> S 0x1002
C 0x2001 -> S 0x2002 + 0x6002 + 0x4013 (hello seq4)
C 0x4013 seq3 = f0 (112B device report)
S ... đẩy dữ liệu lobby (0x4013) nếu token đã được server tin
```

## 5. Garena OAuth (clientless, username/password)

```
GET  /api/prelogin?app_id=100054&account=...        -> v1, v2 (salt)
E    = MD5(password)
inner= SHA256(hex(E)+v1); key = SHA256(hex(inner)+v2)
pw   = AES-256-ECB(key, E).hex()
GET  /api/login?...&password=pw                     -> session_key
POST /oauth/token/grant  (client_id=100054, source=2, client_type=2)
POST /oauth/token/exchange (grant_type=authorization_code, device_id, ...)
```
DataDome chặn prelogin từ IP lạ; cần cookie `datadome` hợp lệ (lấy 1 lần bằng Chrome).

## 6. MSDK itop login (app-like)

```
POST https://itop.kg.garena.vn/v2/auth/login
query: channelid=10&encrypt=1&gameid=1137&os=1&seq=1137-<guest_id>-<ts>-<rand>
       &ts=<ts>&version=5.36.007
body : XOR+base64(JSON) với key = md5("MSDK_ENCRYPT"+SDK_KEY+sig)
sig  : md5("/v2/auth/login?"+query+SDK_KEY+plaintext) + "1"
JSON : {device_info:{uuid,resolution,...}, channel_dis:"00000000", scenes:1,
        scenes_version:2, channel_info:{token: garena_access_token, uid: garena_open_id},
        region:["","",""]}
```
Response trả `token` (MSDK game token), `openid` (game openid), `pf`, `first`, ...

## 7. Tại sao cần brute tail

Server chỉ chấp nhận `0x2001` khi 2-byte tail = hàm của token. Tail 16-bit không suy ra
được từ token đã biết (đã thử nhiều công thức hash/CRC), nên tool dò song song ~24 thread,
thường 1–3 phút/token, lưu cache `captures/token_tails.json`.
