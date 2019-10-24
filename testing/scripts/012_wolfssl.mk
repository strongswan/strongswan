#!/usr/bin/make

PKG = wolfssl
REV = 4.7.1r
DIR = $(PKG)-$(REV)
TAR = v$(REV).tar.gz
SRC = https://github.com/wolfSSL/$(PKG)/archive/refs/tags/$(TAR)

NUM_CPUS := $(shell getconf _NPROCESSORS_ONLN)

CFLAGS = \
	-DWOLFSSL_PUBLIC_MP \
	-DWOLFSSL_DES_ECB \
	-DHAVE_AES_ECB \
	-DHAVE_ECC_BRAINPOOL \
	-DWOLFSSL_MIN_AUTH_TAG_SZ=8 \
	-DHAVE_EX_DATA

CONFIG_OPTS = \
	--disable-crypttests \
	--disable-examples \
	--enable-silent-rules \
	--enable-aesccm \
	--enable-aesctr \
	--enable-ecccustcurves \
	--enable-curve25519 \
	--enable-ed25519 \
	--enable-curve448 \
	--enable-ed448 \
	--enable-rsapss \
	--enable-des3 \
	--enable-sha3 \
	--enable-shake256 \
	--enable-md4 \
	--enable-camellia \
	--enable-keygen \
	--enable-certgen \
	--enable-certreq \
	--enable-certext \
	--enable-sessioncerts

all: install

$(TAR):
	wget $(SRC)

.$(PKG)-unpacked-$(REV): $(TAR)
	[ -d $(DIR) ] || tar xf $(TAR)
	@touch $@

.$(PKG)-built-$(REV): .$(PKG)-unpacked-$(REV)
	cd $(DIR) && ./autogen.sh && ./configure C_FLAGS="$(CFLAGS)" $(CONFIG_OPTS) && make -j $(NUM_CPUS)
	@rm -f .$(PKG)-built-* && touch $@

install: .$(PKG)-built-$(REV)
	cd $(DIR) && make install && ldconfig
