#!/usr/bin/make

PKG = tkm-rpc
SRC = https://git.codelabs.ch/git/$(PKG).git
REV = 1f4e1c9c6ec473cdb391b5416f38d48b09cb6004

PREFIX = /usr/local/ada

export ADA_PROJECT_PATH=$(PREFIX)/lib/gnat

all: install

.$(PKG)-cloned:
	[ -d $(PKG) ] || git clone $(SRC) $(PKG)
	@touch $@

.$(PKG)-checkout-$(REV): .$(PKG)-cloned
	cd $(PKG) && git fetch && git checkout $(REV)
	@rm -f .$(PKG)-checkout-* && touch $@

.$(PKG)-built-$(REV): .$(PKG)-checkout-$(REV)
	cd $(PKG) && make
	@rm -f .$(PKG)-built-* && touch $@

install: .$(PKG)-built-$(REV)
	cd $(PKG) && make PREFIX=$(PREFIX) install
