#
#    This file is part of Octra Wallet (webcli).
#
#    Octra Wallet is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    Octra Wallet is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Octra Wallet.  If not, see <http://www.gnu.org/licenses/>.
#
#    This program is released under the GPL with the additional exemption
#    that compiling, linking, and/or using OpenSSL is allowed.
#    You are free to remove this exemption from derived works.
#
#    Copyright 2025-2026 Octra Labs
#              2025-2026 David A.
#              2025-2026 Alex T.
#              2025-2026 Vadim S.
#              2025-2026 Julia L.
#

CXX:=g++
CC:=gcc
UNAME_M:=$(shell uname -m)
UNAME_S:=$(shell uname -s)
IS_WIN:=$(findstring MINGW,$(UNAME_S))$(findstring MSYS,$(UNAME_S))
ifeq ($(UNAME_M),arm64)
ARCH:=-march=armv8-a+crypto
else
ARCH:=-march=native
endif
CXXFLAGS:=-std=c++17 -O2 $(ARCH) -Wall -pthread
CFLAGS:=-O2 $(ARCH) -Wall
PVAC_DIR:=pvac
PVAC_BUILD:=$(PVAC_DIR)/build
TEST_BUILD := build
EMBEDDED_INC := -I$(PVAC_DIR)/include -I$(PVAC_DIR)

ifeq ($(UNAME_S),Darwin)

SHARED_EXT:=dylib
SHARED_FLAGS:=-dynamiclib
SSL_PREFIX:=$(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl@3)
LDB_PREFIX:=$(shell brew --prefix leveldb 2>/dev/null || echo /opt/homebrew/opt/leveldb)
CXXFLAGS+=-I$(SSL_PREFIX)/include -I$(LDB_PREFIX)/include -DCPPHTTPLIB_OPENSSL_SUPPORT
LDFLAGS:=-L$(SSL_PREFIX)/lib -lssl -lcrypto -L$(LDB_PREFIX)/lib -lleveldb -L$(PVAC_BUILD) -lpvac -Wl,-rpath,@executable_path/$(PVAC_BUILD)
TEST_LDFLAGS := -L$(SSL_PREFIX)/lib -lssl -lcrypto
TEST_PVAC_LDFLAGS := -L$(PVAC_BUILD) -lpvac $(TEST_LDFLAGS) -Wl,-rpath,@loader_path/../$(PVAC_BUILD)
TARGET:=octra_wallet

else ifneq ($(IS_WIN),)

SHARED_EXT:=a
SHARED_FLAGS:=
SSL_PREFIX:=$(shell echo $$MINGW_PREFIX)
LDB_PREFIX:=$(shell echo $$MINGW_PREFIX)
CXXFLAGS+=-I$(SSL_PREFIX)/include -DCPPHTTPLIB_OPENSSL_SUPPORT
LDFLAGS:=-static -L$(SSL_PREFIX)/lib -L$(PVAC_BUILD) -lpvac -lleveldb -lssl -lcrypto -lws2_32 -lbcrypt -lcrypt32 -lgdi32 -lz
TEST_LDFLAGS := -L$(SSL_PREFIX)/lib -lssl -lcrypto -lws2_32 -lbcrypt -lcrypt32
TEST_PVAC_LDFLAGS := -L$(PVAC_BUILD) -lpvac $(TEST_LDFLAGS)
TARGET:=octra_wallet.exe

else

SHARED_EXT:=so
SHARED_FLAGS:=-shared
CXXFLAGS+=-DCPPHTTPLIB_OPENSSL_SUPPORT
LDFLAGS:=-lssl -lcrypto -lleveldb -L$(PVAC_BUILD) -lpvac -Wl,-rpath,'$$ORIGIN/$(PVAC_BUILD)'
TEST_LDFLAGS := -lssl -lcrypto
TEST_PVAC_LDFLAGS := -L$(PVAC_BUILD) -lpvac $(TEST_LDFLAGS) -Wl,-rpath,'$$ORIGIN/../$(PVAC_BUILD)'
TARGET:=octra_wallet

endif

CXXFLAGS+=-I$(PVAC_DIR)
LIBPVAC:=$(PVAC_BUILD)/libpvac.$(SHARED_EXT)
PVAC_HEADERS:=$(shell find $(PVAC_DIR)/include -type f) $(PVAC_DIR)/pvac_c_api.h $(PVAC_DIR)/pvac_serialize.hpp

all: check-deps $(TARGET)

LEVELDB_PATHS:=/usr/include/leveldb/db.h /usr/local/include/leveldb/db.h /opt/homebrew/include/leveldb/db.h /opt/local/include/leveldb/db.h /mingw64/include/leveldb/db.h /ucrt64/include/leveldb/db.h /clang64/include/leveldb/db.h $(LDB_PREFIX)/include/leveldb/db.h
OPENSSL_PATHS:=/usr/include/openssl/evp.h /usr/local/include/openssl/evp.h /opt/homebrew/include/openssl/evp.h /opt/local/include/openssl/evp.h /mingw64/include/openssl/evp.h /ucrt64/include/openssl/evp.h /clang64/include/openssl/evp.h $(SSL_PREFIX)/include/openssl/evp.h

HAVE_LEVELDB:=$(shell for p in $(LEVELDB_PATHS); do [ -f "$$p" ] && { echo yes; exit 0; }; done; echo no)
HAVE_OPENSSL:=$(shell for p in $(OPENSSL_PATHS); do [ -f "$$p" ] && { echo yes; exit 0; }; done; echo no)

check-deps:
ifeq ($(OCTRA_SKIP_AUTOSETUP),)
ifeq ($(HAVE_LEVELDB)$(HAVE_OPENSSL),yesyes)
	@true
else
	@echo 'missing dependencies (leveldb=$(HAVE_LEVELDB) openssl=$(HAVE_OPENSSL))'
	@echo 'running ./setup.sh --deps-only to install...'
	@echo ''
	@if [ -x ./setup.sh ]; then \
		./setup.sh --deps-only || { \
			echo ''; \
			echo 'auto-install failed. install manually:'; \
			echo '  sudo apt install libleveldb-dev libssl-dev   (debian/ubuntu)'; \
			echo '  brew install leveldb openssl@3               (macos)'; \
			echo '  setup.bat from cmd.exe                       (windows)'; \
			exit 1; \
		}; \
	else \
		echo 'setup.sh not found. install manually:'; \
		echo '  sudo apt install libleveldb-dev libssl-dev       (debian/ubuntu)'; \
		echo '  brew install leveldb openssl@3                   (macos)'; \
		echo '  setup.bat from cmd.exe                           (windows)'; \
		exit 1; \
	fi
	@ok=no; for p in $(LEVELDB_PATHS); do [ -f "$$p" ] && ok=yes; done; \
		[ "$$ok" = "yes" ] || { echo 'error: leveldb still missing. on windows run setup.bat from cmd.exe'; exit 1; }
	@ok=no; for p in $(OPENSSL_PATHS); do [ -f "$$p" ] && ok=yes; done; \
		[ "$$ok" = "yes" ] || { echo 'error: openssl still missing. on windows run setup.bat from cmd.exe'; exit 1; }
endif
else
	@true
endif

$(PVAC_BUILD):
	@mkdir -p $(PVAC_BUILD)

$(TEST_BUILD):
	@mkdir -p $(TEST_BUILD)

$(LIBPVAC): $(PVAC_DIR)/pvac_c_api.cpp $(PVAC_HEADERS) | $(PVAC_BUILD)
ifneq ($(IS_WIN),)
	$(CXX) $(CXXFLAGS) -c -I$(PVAC_DIR)/include -o $(PVAC_BUILD)/pvac_c_api.o $<
	ar rcs $@ $(PVAC_BUILD)/pvac_c_api.o
else
	$(CXX) $(CXXFLAGS) -fPIC $(SHARED_FLAGS) -I$(PVAC_DIR)/include -o $@ $<
ifeq ($(UNAME_S),Darwin)
	install_name_tool -id @rpath/libpvac.$(SHARED_EXT) $@
endif
endif

lib/tweetnacl.o: lib/tweetnacl.c
	$(CC) $(CFLAGS) -c -o $@ $<

lib/randombytes.o: lib/randombytes.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): main.cpp rpc_client.hpp lib/endpoint_policy.hpp lib/pvac_map.hpp lib/pvac_upgrade_policy.hpp lib/stealth_scan.hpp lib/tweetnacl.o lib/randombytes.o $(LIBPVAC)
	$(CXX) $(CXXFLAGS) -o $@ main.cpp lib/tweetnacl.o lib/randombytes.o $(LDFLAGS)

clean:
	rm -f $(TARGET) lib/*.o
	rm -rf $(PVAC_BUILD)
	rm -rf $(TEST_BUILD)

run: $(TARGET)
	./$(TARGET) 8420

test-circle-bridge: | $(TEST_BUILD)
	node --test tests/circle_bridge_policy.test.js tests/circle_asset_chunks.test.js tests/security_boundaries.test.js
	$(CXX) $(CXXFLAGS) -o $(TEST_BUILD)/test_circle_asset_chunks tests/circle_asset_chunks.cpp $(TEST_LDFLAGS)
	./$(TEST_BUILD)/test_circle_asset_chunks
	$(CXX) $(CXXFLAGS) -o $(TEST_BUILD)/test_wallet_policy tests/wallet_policy.cpp $(TEST_LDFLAGS)
	./$(TEST_BUILD)/test_wallet_policy

test-pvac-embedded: | $(TEST_BUILD)
	$(CXX) $(CXXFLAGS) $(EMBEDDED_INC) -o $(TEST_BUILD)/test_pvac_embedded tests/pvac_embedded_regression.cpp $(TEST_LDFLAGS)
	./$(TEST_BUILD)/test_pvac_embedded

test-pvac-structure: $(LIBPVAC) | $(TEST_BUILD)
	$(CXX) $(CXXFLAGS) $(EMBEDDED_INC) -o $(TEST_BUILD)/test_pvac_structure tests/pvac_cipher_structure.cpp $(TEST_PVAC_LDFLAGS)
	./$(TEST_BUILD)/test_pvac_structure

test-crypto-boundaries: lib/tweetnacl.o lib/randombytes.o | $(TEST_BUILD)
	$(CXX) $(CXXFLAGS) -o $(TEST_BUILD)/test_crypto_boundaries tests/crypto_boundary_regression.cpp lib/tweetnacl.o lib/randombytes.o $(TEST_LDFLAGS)
	./$(TEST_BUILD)/test_crypto_boundaries
	$(CXX) $(CXXFLAGS) -o $(TEST_BUILD)/test_stealth_scan tests/stealth_scan.cpp $(TEST_LDFLAGS)
	./$(TEST_BUILD)/test_stealth_scan

.PHONY: all clean run check-deps test-circle-bridge test-pvac-embedded test-pvac-structure test-crypto-boundaries