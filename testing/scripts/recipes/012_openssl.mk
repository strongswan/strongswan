#!/usr/bin/make

PV  = 1.0.1e
PKG = openssl-$(PV)
TAR = $(PKG).tar.gz
SRC = http://www.openssl.org/source/$(TAR)

CONFIG_OPTS = \
	--prefix=/usr
all: install

$(TAR):
	wget $(SRC)

$(PKG): $(TAR)
	tar xfz $(TAR)

configure: $(PKG)
	cd $(PKG) && ./config fips shared $(CONFIG_OPTS)

build: configure
	cd $(PKG) && make

install: build
	cd $(PKG) && make install

