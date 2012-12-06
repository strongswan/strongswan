#!/usr/bin/make

PV  = 1.4.16.3
PKG = iptables-$(PV)
TAR = $(PKG).tar.bz2
SRC = http://www.netfilter.org/projects/iptables/files/$(TAR)

NUM_CPUS := $(shell getconf _NPROCESSORS_ONLN)

CONFIG_OPTS =

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
