#!/usr/bin/make

PKG = wolfssl
REV = 4.7.0-commercial-fips-ready
DIR = $(PKG)-$(REV)

NUM_CPUS := $(shell getconf _NPROCESSORS_ONLN)

CFLAGS = \
	-DWOLFSSL_PUBLIC_MP \
	-DWOLFSSL_DES_ECB \
	-DHAVE_AES_ECB \
	-DHAVE_EX_DATA

CONFIG_OPTS = \
    --enable-fips=ready \
	--disable-examples \
	--enable-silent-rules \
	--enable-aesccm \
	--enable-aesctr \
	--enable-rsapss \
	--enable-keygen \
	--enable-certgen \
	--enable-certreq \
	--enable-certext \
	--enable-sessioncerts

all: install

.$(PKG)-built-$(REV):
	cd $(DIR) && ./configure C_FLAGS="$(CFLAGS)" $(CONFIG_OPTS) && make -j $(NUM_CPUS) && \
	./wolfcrypt/test/testwolfcrypt && make check
	@rm -f .$(PKG)-built-* && touch $@

install: .$(PKG)-built-$(REV)
	cd $(DIR) && make install && ldconfig
