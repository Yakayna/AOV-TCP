@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
echo.
echo Da cai dat xong. Hay chay Start.cmd
pause
