#!/usr/bin/env bash

OS="$(uname -s)"

case "$OS" in
    Darwin)
        echo "[1/3] macOS detected"
        if ! command -v brew &>/dev/null; then
            echo "homebrew not found. Installing..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        if ! brew list openssl@3 &>/dev/null; then
            echo "installing OpenSSL..."
            brew install openssl@3
        else
            echo "openSSL already installed"
        fi
        if ! command -v g++ &>/dev/null; then
            echo "installing Xcode command line tools..."
            xcode-select --install 2>/dev/null || true
        fi
        ;;
    Linux)
        echo "[1/3] linux detected"
        if command -v apt-get &>/dev/null; then
            echo "Installing dependencies (apt)..."
            sudo apt-get update -qq 2>/dev/null || true
            sudo apt-get install -y -qq g++ libssl-dev make
        elif command -v dnf &>/dev/null; then
            echo "Installing dependencies (dnf)..."
            sudo dnf install -y gcc-c++ openssl-devel make
        elif command -v pacman &>/dev/null; then
            echo "Installing dependencies (pacman)..."
            sudo pacman -S --noconfirm gcc openssl make
        elif command -v apk &>/dev/null; then
            echo "Installing dependencies (apk)..."
            sudo apk add g++ openssl-dev make
        else
            echo "Unknown package manager. Please install: g++, libssl-dev, make"
            exit 1
        fi
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "on windows, use setup.bat instead."
        exit 1
        ;;
esac

echo ""
echo "[2/3] building octra wallet and other things"
make clean 2>/dev/null || true
if ! make; then
    echo ""
    echo "build failed."
    exit 1
fi

echo ""
echo "[3/3] done!"
echo ""
echo "start the wallet:"
echo "./octra_wallet"
echo ""
echo "then open http://127.0.0.1:8420 in your browser."
echo ""
