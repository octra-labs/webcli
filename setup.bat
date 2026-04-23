@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

set "MSYS2_DIR="
if exist "C:\msys64\usr\bin\bash.exe" set "MSYS2_DIR=C:\msys64"
if exist "%USERPROFILE%\msys64\usr\bin\bash.exe" set "MSYS2_DIR=%USERPROFILE%\msys64"
if exist "D:\msys64\usr\bin\bash.exe" set "MSYS2_DIR=D:\msys64"
if exist "C:\tools\msys64\usr\bin\bash.exe" set "MSYS2_DIR=C:\tools\msys64"

if defined MSYS2_DIR (
    echo [1/3] MSYS2 found at !MSYS2_DIR!
    goto :install_deps
)

echo [1/3] MSYS2 not found. installing...
echo.

where winget >nul 2>&1
if %errorlevel% equ 0 (
    echo installing MSYS2 via winget...
    winget install --id MSYS2.MSYS2 --accept-source-agreements --accept-package-agreements -e
    goto :verify_msys2
)

where choco >nul 2>&1
if %errorlevel% equ 0 (
    echo installing MSYS2 via chocolatey...
    choco install -y msys2
    goto :verify_msys2
)

where scoop >nul 2>&1
if %errorlevel% equ 0 (
    echo installing MSYS2 via scoop...
    scoop bucket add extras
    scoop install msys2
    goto :verify_msys2
)

echo no package manager found (winget / choco / scoop).
echo.
echo please install MSYS2 manually from:
echo https://www.msys2.org/
echo.
echo after installing, re-run this script.
pause
exit /b 1

:verify_msys2
if exist "C:\msys64\usr\bin\bash.exe" set "MSYS2_DIR=C:\msys64"
if exist "%USERPROFILE%\msys64\usr\bin\bash.exe" set "MSYS2_DIR=%USERPROFILE%\msys64"

if not defined MSYS2_DIR (
    echo MSYS2 installation did not land in a known location.
    echo please install manually from https://www.msys2.org/
    pause
    exit /b 1
)

:install_deps
echo installing compiler + dependencies (openssl, leveldb)...
"!MSYS2_DIR!\usr\bin\bash.exe" -lc "pacman -Syu --noconfirm --needed"
"!MSYS2_DIR!\usr\bin\bash.exe" -lc "pacman -S --noconfirm --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl mingw-w64-x86_64-leveldb mingw-w64-x86_64-pkgconf make"

if %errorlevel% neq 0 (
    echo dependency installation failed.
    pause
    exit /b 1
)

echo.
echo [2/3] building octra wallet...

set "WALLET_DIR=%~dp0"
set "WALLET_DIR_UNIX=%WALLET_DIR:\=/%"

"!MSYS2_DIR!\usr\bin\bash.exe" -lc "export PATH=/mingw64/bin:$PATH && cd '%WALLET_DIR_UNIX%' && make clean 2>/dev/null; make"

if not exist "%WALLET_DIR%octra_wallet.exe" (
    echo.
    echo build failed. check errors above.
    pause
    exit /b 1
)

echo.
echo [3/3] done
echo.
echo start the wallet:
echo octra_wallet.exe
echo.
echo then open http://127.0.0.1:8420 in your browser
echo.
pause