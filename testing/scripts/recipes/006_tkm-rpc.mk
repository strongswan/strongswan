#!/usr/bin/make

PKG = tkm-rpc
SRC = http://git.codelabs.ch/git/$(PKG).git
REV = v0.1

PREFIX = /usr/local/ada

export ADA_PROJECT_PATH=$(PREFIX)/lib/gnat

all: install

.$(PKG)-cloned:
	git clone $(SRC) $(PKG)
	cd $(PKG) && git checkout $(REV)
	@touch $@

.$(PKG)-built: .$(PKG)-cloned
	cd $(PKG) && make
	@touch $@

install: .$(PKG)-built
	cd $(PKG) && make PREFIX=$(PREFIX) install
