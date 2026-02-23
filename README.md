# octra wallet (webcli)
![Version](https://img.shields.io/badge/version-0.04.01--alpha-blue)


a full-fledged web client based on a local server for working with the octra network (currently available only for **DEVNET** and not compatible with the main network for RPC calls, but will be merged soon).

you can send txs, encrypt and decrypt balances, conduct stealth txs, and much more

## requirements

- c++17 compiler (GCC/Clang)
- openSSL 3.x
- libpvac (from `pvac/` directory)


### macOS (homebrew)

```
brew install openssl@3
```

### linux (debian or ubuntu)

```
sudo apt install g++ libssl-dev make
```

then (valid for both)

```
chmod +x setup.sh
./setup.sh
./octra_wallet
```

### windows

double click `setup.bat` or run it from command prompt
it will install everything automatically and then:

```
octra_wallet.exe
```

open `http://127.0.0.1:8420` in your browser


### windows (MSYS2)

install [MSYS2](https://www.msys2.org/), open MinGW64 shell:

```
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make
```

## build

```
make
```

## run

```
./octra_wallet # default port 8420
./octra_wallet 9000 # custom port
```

on windows:

```
octra_wallet.exe
octra_wallet.exe 9000
```

open `http://127.0.0.1:8420` in your browser

## launch

0. after opening the web interface in your browser, import your private key or create a new one directly in the modal window
1. enter a 6 digit PIN code to encrypt (AES 256 GCM) your wallet 
2. your wallet file is stored in `data/wallet.oct` 
3. the PIN is required on every startup to unlock


we adhere to a policy of completely eliminating third-party software where possible, we have zero tolerance for vendor dependencies, we only included well-known libs and point implementations in the build, the rest was completely written from scratch by hand to avoid the use of third-party code for security reasons

## vendor libraries

- [cpp-httplib](https://github.com/yhirose/cpp-httplib) (MIT)
- [nlohmann/json](https://github.com/nlohmann/json) (MIT)
- [TweetNaCl](https://tweetnacl.cr.yp.to/) (public domain)