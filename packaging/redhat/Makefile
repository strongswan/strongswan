# FreeS/WAN RedHat RPM makefile
# Copyright (C) 2002  Michael Richardson <mcr@freeswan.org>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.1 2004/03/15 20:35:27 as Exp $

FREESWANSRCDIR=$(shell cd ../.. && pwd)
include ${FREESWANSRCDIR}/Makefile.inc
include ${FREESWANSRCDIR}/Makefile.ver


# temporary directory to be used when building RPMs, and where to put the
# resulting RPM tree
RPMKERNDIR := $(shell echo `pwd`/tmp.rpmkernel)
RPMTMPDIR=$(shell echo `pwd`/tmp.rpmbuild)
RPMDEST := $(shell echo `pwd`/rpms)

# definitions from main Makefile that may be relevant

KERNELKLIPS=$(KERNELSRC)/net/ipsec
KERNELCRYPTODES=$(KERNELSRC)/crypto/ciphers/des
KERNELLIBFREESWAN=$(KERNELSRC)/lib/libfreeswan
KERNELLIBZLIB=$(KERNELSRC)/lib/zlib
KERNELINCLUDE=$(KERNELSRC)/include

MAKEUTILS=${FREESWANSRCDIR}/packaging/utils
ERRCHECK=${MAKEUTILS}/errcheck
KVUTIL=${MAKEUTILS}/kernelversion
KVSHORTUTIL=${MAKEUTILS}/kernelversion-short


clean:	
	rm -rf $(shell echo `pwd`/BUILD.*)
	rm -rf ${RPMTMPDIR}
	rm -rf ${RPMDEST} 
	rm -f $(shell echo `pwd`/rpm.spec)

rpm:	rpm_userland rpm_modules rpm.spec final_rpm

# RPM-build userland install in temporary directory
rpm_userland: clean
	mkdir -p $(RPMTMPDIR)
	(cd ${FREESWANSRCDIR} && $(MAKE) programs install DESTDIR=$(RPMTMPDIR) && cd `pwd`)
	for extras in README CHANGES ; do \
		cp -f $(FREESWANSRCDIR)/$$extras $(RPMTMPDIR)$(FINALEXAMPLECONFDIR)/ ; \
	done

rpm_modules:
	@if [ ! -d ${RH_KERNELSRC}/configs ]; then echo "Please fix RH_KERNELSRC in Makefile.inc (${RH_KERNELSRC})"; exit 1; fi
	@KV=`${KVUTIL} $(RH_KERNELSRC)/Makefile | sed -e 's/custom//'` ; \
	MD=${RPMTMPDIR}/lib/modules/$$KV/kernel/net/ipsec; mkdir -p $$MD; \
	echo Installing into $$MD for $$KV; \
	rm -rf BUILD.*; \
	cat kernel-list.txt | while read kerneltype arch subarch; \
	do \
	    mkdir -p BUILD.$$kerneltype; \
	    if [ -z "$$subarch" ]; then subarch=$$arch; fi; \
	    BUILDDIR=`pwd`/BUILD.$$kerneltype; \
	    HERE=`pwd` ;\
	    echo Building $$KV-$$kerneltype in $$BUILDDIR; \
	    ${MAKE} -C ${FREESWANSRCDIR} MODBUILDDIR=$$BUILDDIR KERNELSRC=${RH_KERNELSRC} ARCH=$$arch SUBARCH=$$subarch MODULE_DEF_INCLUDE=$$HERE/config-$$kerneltype.h module;\
	    cp $$BUILDDIR/ipsec.o $$MD/ipsec.o-$$kerneltype; \
	    goo="`nm -ao $$BUILDDIR/ipsec.o | ${FREESWANSRCDIR}/programs/calcgoo/calcgoo`"; \
	    (cd $$MD && ln -f ipsec.o-$$kerneltype $$goo); \
	done

# build spec file for building RPMs
rpm.spec:	rpm.in $(RH_KERNELSRC)/Makefile
	KVORIG=`${KVUTIL} $(RH_KERNELSRC)/Makefile | sed -e 's/custom//'` ; \
	KV=`echo $$KVORIG | sed -e 's/-/_/g' ` ; \
	IPSECVERSIONFIXED=`echo ${IPSECVERSION} | sed -e 's/-/_/g'`; \
	echo KVORIG: $$KVORIG KV: $$KV IV: $$IPSECVERSIONFIXED; \
	sed -e "/@KERNELVERSION@/s;;$$KV;" \
		-e "/@KERNELVERSIONORIG@/s;;$$KVORIG;" \
		-e "/@IPSECVERSION@/s;;$$IPSECVERSIONFIXED;" \
		-e '/@PUBDIR@/s;;$(PUBDIR);' \
		-e '/@FINALBINDIR@/s;;$(FINALBINDIR);' \
		-e '/@FINALLIBDIR@/s;;$(FINALLIBDIR);' \
		-e '/@FINALCONFDDIR@/s;;$(FINALCONFDDIR);' \
		-e '/@FINALCONFDIR@/s;;$(FINALCONFDIR);' \
		-e '/@FINALEXAMPLECONFDIR@/s;;$(FINALEXAMPLECONFDIR);' \
		-e '/@MANTREE@/s;;$(MANTREE);' rpm.in > rpm.spec

# build RPMs
final_rpm:	rpm.spec
	mkdir -p $(RPMDEST)
	cd $(RPMDEST) ; mkdir -p SRPMS BUILD RPMS SPECS SOURCES
	cd $(RPMDEST)/RPMS ; mkdir -p $(ARCH) noarch
	$(RPMBUILD) -bb --define "buildroot $(RPMTMPDIR)" \
		--define "_topdir $(RPMDEST)" rpm.spec
	# that has, incidentally, gotten rid of $(RPMTMPDIR)
