#!/usr/bin/make

PKG = strongTNC
ZIP = $(PKG)-master.zip
SRC = https://github.com/strongswan/$(PKG)/archive/master.zip

all: install

$(ZIP):
	wget --ca-directory=/usr/share/ca-certificates/mozilla/ $(SRC) -O $(ZIP)

$(PKG)-master: $(ZIP)
	unzip -u $(ZIP)

install: $(PKG)-master
	cd $(PKG)-master && pip install -r requirements.txt
	cp -r $(PKG)-master /var/www/tnc && chgrp -R www-data /var/www/tnc
