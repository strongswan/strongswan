
SOURCE:=../../src/charon/plugins/nm/gnome
VERSION:=1.0.0

source:	prepare
	cd build/NetworkManager-strongswan-$(VERSION) && debuild -S

prepare: clean
	mkdir build
	make -C $(SOURCE) dist-gzip
	mv $(SOURCE)/NetworkManager-strongswan-$(VERSION).tar.gz build/network-manager-strongswan_$(VERSION).orig.tar.gz
	tar -zxv -C build -f build/network-manager-strongswan_$(VERSION).orig.tar.gz
	dch -b -v $(VERSION)
	cp -R debian build/NetworkManager-strongswan-$(VERSION)

clean:
	rm -Rf build

.PHONY:	source prepare clean
