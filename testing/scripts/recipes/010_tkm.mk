#!/usr/bin/make

PKG = tkm
SRC = https://git.codelabs.ch/git/$(PKG).git
ifeq (,$(filter $(BASEIMG),bullseye bookworm))
REV = d1f002db4182f8f09ee5c8ef5d7ddb187cf837fe
else
REV = v0.3
endif

export ADA_PROJECT_PATH=/usr/local/ada/lib/gnat

all: install

.$(PKG)-cloned:
	[ -d $(PKG) ] || git clone $(SRC) $(PKG)
	@touch $@

.$(PKG)-checkout-$(REV): .$(PKG)-cloned
	cd $(PKG) && git fetch && git checkout $(REV)
	@rm -f .$(PKG)-checkout-* && touch $@

.$(PKG)-built-$(REV): .$(PKG)-checkout-$(REV)
	cd $(PKG) && make tests && make
	@rm -f .$(PKG)-built-* && touch $@

install: .$(PKG)-built-$(REV)
	cd $(PKG) && make install
