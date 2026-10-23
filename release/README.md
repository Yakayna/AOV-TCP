# Lien Quan Mobile - Clientless Lobby Runner

Cong cu dang nhap bang tai khoan/mat khau Garena va dua nhan vat vao sanh
(giu ket noi 24/7) ma **khong can mo game client / LDPlayer**.

## Yeu cau
- Windows 10/11
- Python 3.10+ (https://python.org)
- Google Chrome (de giai captcha Garena khi duoc yeu cau)
- Internet

## Cai dat
1. Chay `setup.cmd` (cai playwright + cryptography).
2. Chay `Start.cmd`.

## Su dung
1. Nhap tai khoan + mat khau Garena.
2. Neu Chrome hien captcha, giai captcha va khong dong cua so.
3. Cho den khi thay:
   - `DA VAO SANH. Dang duy tri ket noi 24/7.`
   - `ONLINE | dang duy tri ket noi ...`
4. Giu cua so CMD mo de duy tri ket noi. Ctrl+C de dung.

## Ghi chu
- Chi hoat dong voi client Lien Quan Mobile VN 1.64.1.7.
- Tai khoan can co nhan vat trong game.
- Chi tiet loi: `app/logs/latest.log`
