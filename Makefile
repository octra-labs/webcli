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
#              2025-2026 lambda0xe
#              dev[at]octra.org
#              2025-2026 Aleksandr Tsereteli
#              alex[at]octra.org
#              2025-2026 Vadim S.
#              2025-2026 Julia Lezra
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

ifeq ($(UNAME_S),Darwin)

SHARED_EXT:=dylib
SHARED_FLAGS:=-dynamiclib
SSL_PREFIX:=$(shell brew --prefix openssl 2>/dev/null || echo /usr/local/opt/openssl)
CXXFLAGS+=-I$(SSL_PREFIX)/include -DCPPHTTPLIB_OPENSSL_SUPPORT
LDFLAGS:=-L$(SSL_PREFIX)/lib -lssl -lcrypto -L$(PVAC_BUILD) -lpvac -Wl,-rpath,@executable_path/$(PVAC_BUILD)
TARGET:=octra_wallet

else ifneq ($(IS_WIN),)

SHARED_EXT:=dll
SHARED_FLAGS:=-shared
SSL_PREFIX:=$(shell echo $$MINGW_PREFIX)
CXXFLAGS+=-I$(SSL_PREFIX)/include -DCPPHTTPLIB_OPENSSL_SUPPORT
LDFLAGS:=-L$(SSL_PREFIX)/lib -lssl -lcrypto -lws2_32 -lbcrypt -L$(PVAC_BUILD) -lpvac
TARGET:=octra_wallet.exe

else

SHARED_EXT:=so
SHARED_FLAGS:=-shared
CXXFLAGS+=-DCPPHTTPLIB_OPENSSL_SUPPORT
LDFLAGS:=-lssl -lcrypto -L$(PVAC_BUILD) -lpvac -Wl,-rpath,'$$ORIGIN/$(PVAC_BUILD)'
TARGET:=octra_wallet

endif

CXXFLAGS+=-I$(PVAC_DIR)
LIBPVAC:=$(PVAC_BUILD)/libpvac.$(SHARED_EXT)

all: $(TARGET)

$(PVAC_BUILD):
	@mkdir -p $(PVAC_BUILD)

$(LIBPVAC): $(PVAC_DIR)/pvac_c_api.cpp | $(PVAC_BUILD)
ifneq ($(IS_WIN),)
	$(CXX) $(CXXFLAGS) -fPIC $(SHARED_FLAGS) -I$(PVAC_DIR)/include -o $@ $< -lbcrypt
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

$(TARGET): main.cpp lib/tweetnacl.o lib/randombytes.o $(LIBPVAC)
	$(CXX) $(CXXFLAGS) -o $@ main.cpp lib/tweetnacl.o lib/randombytes.o $(LDFLAGS)
ifneq ($(IS_WIN),)
	@cp $(LIBPVAC) .
endif

clean:
	rm -f $(TARGET) lib/*.o
	rm -rf $(PVAC_BUILD)
ifneq ($(IS_WIN),)
	rm -f libpvac.dll
endif

run: $(TARGET)
	./$(TARGET) 8420

.PHONY: all clean run