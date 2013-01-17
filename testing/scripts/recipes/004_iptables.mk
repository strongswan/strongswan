#!/usr/bin/make

PV  = 1.4.16.3
PKG = iptables-$(PV)
TAR = $(PKG).tar.bz2
SRC = http://www.netfilter.org/projects/iptables/files/$(TAR)

NUM_CPUS := $(shell getconf _NPROCESSORS_ONLN)

CONFIG_OPTS =

PATCHES = \
	iptables-xfrm-hooks

all: install

$(TAR):
	wget $(SRC)

.$(PKG)-unpacked: $(TAR)
	tar xfj $(TAR)
	@touch $@

.$(PKG)-patches-applied: .$(PKG)-unpacked
	cd $(PKG) && cat $(addprefix ../patches/, $(PATCHES)) | patch -p1
	@touch $@

.$(PKG)-configured: .$(PKG)-patches-applied
	cd $(PKG) && ./configure $(CONFIG_OPTS)
	@touch $@

.$(PKG)-built: .$(PKG)-configured
	cd $(PKG) && make -j $(NUM_CPUS)
	@touch $@

install: .$(PKG)-built
	cd $(PKG) && make install
