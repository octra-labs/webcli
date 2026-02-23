@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion


set "MSYS2_DIR="
if exist "C:\msys64\usr\bin\bash.exe" (
    set "MSYS2_DIR=C:\msys64"
)
if exist "%USERPROFILE%\msys64\usr\bin\bash.exe" (
    set "MSYS2_DIR=%USERPROFILE%\msys64"
)

if defined MSYS2_DIR (
    echo [1/3] MSYS2 found at !MSYS2_DIR!
    goto :install_deps
)

echo [1/3] MSYS2 not found. Installing...
echo.

where winget >nul 2>&1
if %errorlevel% equ 0 (
    echo installing MSYS2 via winget...
    winget install --id MSYS2.MSYS2 --accept-source-agreements --accept-package-agreements -e
) else (
    echo winget not available.
    echo.
    echo Please download and install MSYS2 manually from:
    echo https://www.msys2.org/
    echo.
    echo After installing, run this script again.
    pause
    exit /b 1
)

if exist "C:\msys64\usr\bin\bash.exe" (
    set "MSYS2_DIR=C:\msys64"
) else (
    echo MSYS2 installation failed, please install manually from https://www.msys2.org/
    pause
    exit /b 1
)

:install_deps
echo installing compiler and OpenSSL...
"!MSYS2_DIR!\usr\bin\bash.exe" -lc "pacman -S --noconfirm --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make"

echo.
echo [2/3] building octra wallet...

set "WALLET_DIR=%~dp0"
"!MSYS2_DIR!\usr\bin\bash.exe" -lc "export PATH=/mingw64/bin:$PATH && cd '%WALLET_DIR:\=/%' && make clean 2>/dev/null; make"

if not exist "%WALLET_DIR%octra_wallet.exe" (
    echo.
    echo build failed -please check errors above
    pause
    exit /b 1
)

echo.
echo [3/3] done!
echo.
echo start the wallet:
echo octra_wallet.exe
echo.
echo then open http://127.0.0.1:8420 in your browser.
echo.
pause
