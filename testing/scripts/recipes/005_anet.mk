#!/usr/bin/make

PKG = anet
SRC = http://git.codelabs.ch/git/$(PKG).git
REV = v0.2.2

all: install

.$(PKG)-cloned:
	git clone $(SRC) $(PKG)
	cd $(PKG) && git checkout $(REV)
	@touch $@

.$(PKG)-built: .$(PKG)-cloned
	cd $(PKG) && make tests && make LIBRARY_KIND=static
	@touch $@

install: .$(PKG)-built
	cd $(PKG) && make LIBRARY_KIND=static install
