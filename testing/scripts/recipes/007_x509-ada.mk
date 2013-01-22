#!/usr/bin/make

PKG = x509-ada
SRC = http://git.codelabs.ch/git/$(PKG).git
REV = v0.1

all: install

.$(PKG)-cloned:
	git clone $(SRC) $(PKG)
	cd $(PKG) && git checkout $(REV)
	@touch $@

.$(PKG)-built: .$(PKG)-cloned
	cd $(PKG) && make tests && make
	@touch $@

install: .$(PKG)-built
	cd $(PKG) && make install
