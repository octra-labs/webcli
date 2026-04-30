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
            if dpkg -s build-essential g++ libssl-dev libleveldb-dev pkg-config make curl &>/dev/null; then
                echo "dependencies already installed"
            else
                echo "installing dependencies (apt)..."
                $SUDO apt-get update -qq
                $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                    build-essential g++ libssl-dev libleveldb-dev pkg-config make curl
            fi
        elif command -v dnf &>/dev/null; then
            if rpm -q gcc-c++ openssl-devel leveldb-devel make pkgconfig &>/dev/null; then
                echo "dependencies already installed"
            else
                echo "installing dependencies (dnf)..."
                $SUDO dnf install -y gcc-c++ openssl-devel leveldb-devel make pkgconfig
            fi
        elif command -v yum &>/dev/null; then
            if rpm -q gcc-c++ openssl-devel leveldb-devel make pkgconfig &>/dev/null; then
                echo "dependencies already installed"
            else
                echo "installing dependencies (yum)..."
                $SUDO yum install -y gcc-c++ openssl-devel leveldb-devel make pkgconfig
            fi
        elif command -v zypper &>/dev/null; then
            if rpm -q gcc-c++ libopenssl-devel leveldb-devel make pkg-config &>/dev/null; then
                echo "dependencies already installed"
            else
                echo "installing dependencies (zypper)..."
                $SUDO zypper install -y gcc-c++ libopenssl-devel leveldb-devel make pkg-config
            fi
        elif command -v pacman &>/dev/null; then
            if pacman -Q gcc openssl leveldb make pkgconf &>/dev/null; then
                echo "dependencies already installed"
            else
                echo "installing dependencies (pacman)..."
                $SUDO pacman -S --noconfirm --needed gcc openssl leveldb make pkgconf
            fi
        elif command -v apk &>/dev/null; then
            if apk info -e g++ openssl-dev leveldb-dev make pkgconfig musl-dev linux-headers &>/dev/null; then
                echo "dependencies already installed"
            else
                echo "installing dependencies (apk)..."
                $SUDO apk add --no-cache g++ openssl-dev leveldb-dev make pkgconfig musl-dev linux-headers
            fi
        elif command -v emerge &>/dev/null; then
            if ls -d /var/db/pkg/dev-libs/openssl-* /var/db/pkg/dev-libs/leveldb-* /var/db/pkg/sys-devel/gcc-* /var/db/pkg/sys-devel/make-* &>/dev/null; then
                echo "dependencies already installed"
            else
                echo "installing dependencies (emerge)..."
                $SUDO emerge --noreplace dev-libs/openssl dev-libs/leveldb sys-devel/gcc sys-devel/make
            fi
        elif command -v xbps-install &>/dev/null; then
            if xbps-query -l | grep -qE "^ii gcc-" && \
               xbps-query -l | grep -qE "^ii openssl-devel-" && \
               xbps-query -l | grep -qE "^ii leveldb-devel-" && \
               xbps-query -l | grep -qE "^ii make-" && \
               xbps-query -l | grep -qE "^ii pkgconf-"; then
                echo "dependencies already installed"
            else
                echo "installing dependencies (xbps)..."
                $SUDO xbps-install -Sy gcc openssl-devel leveldb-devel make pkgconf
            fi
        else
            echo "unknown package manager. install manually: g++, libssl-dev, libleveldb-dev, make, pkg-config"
            exit 1
        fi
        ;;
    FreeBSD)
        echo "[1/3] FreeBSD detected"
        if pkg info gcc openssl leveldb gmake pkgconf &>/dev/null; then
            echo "dependencies already installed"
        else
            $SUDO pkg install -y gcc openssl leveldb gmake pkgconf
        fi
        ;;
    OpenBSD)
        echo "[1/3] OpenBSD detected"
        if pkg_info g++ openssl leveldb gmake &>/dev/null; then
            echo "dependencies already installed"
        else
            $SUDO pkg_add -I g++ openssl leveldb gmake
        fi
        ;;
    NetBSD)
        echo "[1/3] NetBSD detected"
        if pkg_info gcc openssl leveldb gmake pkg-config &>/dev/null; then
            echo "dependencies already installed"
        else
            $SUDO pkgin install -y gcc openssl leveldb gmake pkg-config
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        if [ "$MODE" = "deps" ]; then
            echo "[1/1] detected windows shell ($OS) in deps-only mode"
            echo "on windows, dependencies should be installed via setup.bat from cmd.exe"
            echo "if you already ran setup.bat, this is fine — continuing"
            exit 0
        fi
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
echo "./octra_wallet"
echo ""
echo "then open http://127.0.0.1:8420 in your browser"
echo ""
