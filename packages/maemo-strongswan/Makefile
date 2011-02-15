SOURCE:=../../
BUILD:=build
VERSION:=$(shell sed -n 's/AC_INIT(.*,\s*\(.*\))/\1/p' $(SOURCE)/configure.in)
TARGETVERSION:=$(VERSION)
ORIGNAME:=strongswan-$(VERSION)
ORIGSRC:=$(BUILD)/strongswan_$(TARGETVERSION).orig.tar.gz

package: prepare
	cd $(BUILD)/$(ORIGNAME) && \
	dpkg-buildpackage -rfakeroot -sa > /dev/null

source: prepare
	cd $(BUILD)/$(ORIGNAME) && \
	dpkg-buildpackage -rfakeroot -sa -S > /dev/null

prepare: $(ORIGSRC)
	rm -Rf $(BUILD)/$(ORIGNAME)
	tar -zx -C $(BUILD) -f $(ORIGSRC)
	debchange -b -v $(TARGETVERSION)-1
	cp -R debian $(BUILD)/$(ORIGNAME)

$(ORIGSRC): $(SOURCE)/Makefile | $(BUILD)
	make -j -C $(SOURCE) dist-gzip > /dev/null
	mv $(SOURCE)/$(ORIGNAME).tar.gz $(ORIGSRC)

$(SOURCE)/Makefile: $(SOURCE)/configure
	cd $(SOURCE) && ./configure --disable-gmp > /dev/null

$(SOURCE)/configure: $(SOURCE)/configure.in
	cd $(SOURCE) && ./autogen.sh > /dev/null

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -Rf $(BUILD)

.PHONY:	package source prepare clean
