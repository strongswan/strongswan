#!/usr/bin/make

PV  = 2.2.0
PKG = freeradius-server-$(PV)
TAR = $(PKG).tar.bz2
SRC = ftp://ftp.freeradius.org/pub/freeradius/$(TAR)

NUM_CPUS := $(shell getconf _NPROCESSORS_ONLN)

CONFIG_OPTS = \
	--with-raddbdir=/etc/freeradius \
	--sysconfdir=/etc \
	--with-logdir=/var/log/freeradius \
	--enable-developer \
	--with-experimental-modules

all: install

$(TAR):
	wget $(SRC)

$(PKG): $(TAR)
	tar xfj $(TAR)

configure: $(PKG)
	cd $(PKG) && ./configure $(CONFIG_OPTS)

build: configure
	cd $(PKG) && make -j $(NUM_CPUS)

install: build
	cd $(PKG) && make install
