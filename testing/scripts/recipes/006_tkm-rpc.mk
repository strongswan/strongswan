#!/usr/bin/make

PKG = tkm-rpc
SRC = http://git.codelabs.ch/git/$(PKG).git
REV = 075d22871cf81d497aac656c7f03a513278b641c

PREFIX = /usr/local/ada

export ADA_PROJECT_PATH=$(PREFIX)/lib/gnat

all: install

.$(PKG)-cloned:
	[ -d $(PKG) ] || git clone $(SRC) $(PKG)
	@touch $@

.$(PKG)-checkout-$(REV): .$(PKG)-cloned
	cd $(PKG) && git fetch && git checkout $(REV)
	@touch $@

.$(PKG)-built-$(REV): .$(PKG)-checkout-$(REV)
	cd $(PKG) && make
	@touch $@

install: .$(PKG)-built-$(REV)
	cd $(PKG) && make PREFIX=$(PREFIX) install
