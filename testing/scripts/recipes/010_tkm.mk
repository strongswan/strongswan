#!/usr/bin/make

PKG = tkm
SRC = http://git.codelabs.ch/git/$(PKG).git
REV = v0.1

export ADA_PROJECT_PATH=/usr/local/ada/lib/gnat

all: install

.$(PKG)-cloned:
	git clone $(SRC) $(PKG)
	cd $(PKG) && git checkout $(REV)
	@touch $@

.$(PKG)-built: .$(PKG)-cloned
	cd $(PKG) && make
	@touch $@

install: .$(PKG)-built
	cd $(PKG) && make install
