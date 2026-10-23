@echo off
chcp 65001 >nul
title Lien Quan Mobile - Dang nhap tu dong
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Khong tim thay Python. Hay cai Python 3.10+ tu python.org
  pause
  exit /b 1
)
python -u "app\show.py"
echo.
echo Nhan phim bat ky de dong...
pause >nul
