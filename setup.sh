#!/usr/bin/env bash
set -e

MODE="full"
for arg in "$@"; do
    case "$arg" in
        --deps-only|--no-build) MODE="deps" ;;
        --help|-h)
            echo "usage: $0 [--deps-only]"
            echo "(no args) install deps + build"
            echo "--deps-only install deps only (no make)"
            exit 0
            ;;
    esac
done

OS="$(uname -s)"

if [ "$(id -u)" = "0" ]; then
    SUDO=""
else
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        SUDO=""
    fi
fi

case "$OS" in
    Darwin)
        echo "[1/3] macOS detected"
        if ! command -v brew &>/dev/null; then
            echo "homebrew not found. installing..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            if [ -d /opt/homebrew/bin ]; then
                eval "$(/opt/homebrew/bin/brew shellenv)"
            elif [ -d /usr/local/bin ] && [ -x /usr/local/bin/brew ]; then
                eval "$(/usr/local/bin/brew shellenv)"
            fi
        fi
        for pkg in openssl@3 leveldb; do
            if ! brew list $pkg &>/dev/null; then
                echo "installing $pkg..."
                brew install $pkg
            else
                echo "$pkg already installed"
            fi
        done
        if ! xcode-select -p &>/dev/null; then
            echo "installing Xcode command line tools..."
            xcode-select --install 2>/dev/null || true
            echo "a GUI installer may have opened. re-run this script after it finishes."
            exit 0
        fi
        ;;
    Linux)
        echo "[1/3] linux detected"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            echo "distro: ${ID:-unknown} ${VERSION_ID:-}"
        fi
        if command -v apt-get &>/dev/null; then
            echo "installing dependencies (apt)..."
            $SUDO apt-get update -qq
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                build-essential g++ libssl-dev libleveldb-dev pkg-config make curl
        elif command -v dnf &>/dev/null; then
            echo "installing dependencies (dnf)..."
            $SUDO dnf install -y gcc-c++ openssl-devel leveldb-devel make pkgconfig
        elif command -v yum &>/dev/null; then
            echo "installing dependencies (yum)..."
            $SUDO yum install -y gcc-c++ openssl-devel leveldb-devel make pkgconfig
        elif command -v zypper &>/dev/null; then
            echo "installing dependencies (zypper)..."
            $SUDO zypper install -y gcc-c++ libopenssl-devel leveldb-devel make pkg-config
        elif command -v pacman &>/dev/null; then
            echo "installing dependencies (pacman)..."
            $SUDO pacman -S --noconfirm --needed gcc openssl leveldb make pkgconf
        elif command -v apk &>/dev/null; then
            echo "installing dependencies (apk)..."
            $SUDO apk add --no-cache g++ openssl-dev leveldb-dev make pkgconfig musl-dev linux-headers
        elif command -v emerge &>/dev/null; then
            echo "installing dependencies (emerge)..."
            $SUDO emerge --noreplace dev-libs/openssl dev-libs/leveldb sys-devel/gcc sys-devel/make
        elif command -v xbps-install &>/dev/null; then
            echo "installing dependencies (xbps)..."
            $SUDO xbps-install -Sy gcc openssl-devel leveldb-devel make pkgconf
        else
            echo "unknown package manager. install manually: g++, libssl-dev, libleveldb-dev, make, pkg-config"
            exit 1
        fi
        ;;
    FreeBSD)
        echo "[1/3] FreeBSD detected"
        $SUDO pkg install -y gcc openssl leveldb gmake pkgconf
        ;;
    OpenBSD)
        echo "[1/3] OpenBSD detected"
        $SUDO pkg_add -I g++ openssl leveldb gmake
        ;;
    NetBSD)
        echo "[1/3] NetBSD detected"
        $SUDO pkgin install -y gcc openssl leveldb gmake pkg-config
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "detected windows shell ($OS). run setup.bat from cmd.exe instead."
        exit 1
        ;;
    *)
        echo "unsupported OS: $OS"
        echo "on windows use setup.bat. please install manually: g++, libssl-dev, libleveldb-dev, make"
        exit 1
        ;;
esac

if [ "$MODE" = "deps" ]; then
    echo ""
    echo "[2/2] dependencies installed (deps-only mode)"
    exit 0
fi

echo ""
echo "[2/3] building octra wallet"

if ! command -v make &>/dev/null; then
    if command -v gmake &>/dev/null; then
        MAKE=gmake
    else
        echo "neither make nor gmake found"
        exit 1
    fi
else
    MAKE=make
fi

OCTRA_SKIP_AUTOSETUP=1 $MAKE clean 2>/dev/null || true
if ! OCTRA_SKIP_AUTOSETUP=1 $MAKE; then
    echo ""
    echo "build failed"
    exit 1
fi

echo ""
echo "[3/3] done"
echo ""
echo "start the wallet:"
echo " ./octra_wallet"
echo ""
echo "then open http://127.0.0.1:8420 in your browser"
echo ""