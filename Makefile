# FreeS/WAN master makefile
# Copyright (C) 1998-2002  Henry Spencer.
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
# RCSID $Id: Makefile,v 1.4 2004/11/14 21:50:59 as Exp $


FREESWANSRCDIR=$(shell pwd)
export FREESWANSRCDIR

include Makefile.inc



PATCHES=linux
# where KLIPS goes in the kernel
# note, some of the patches know the last part of this path
KERNELKLIPS=$(KERNELSRC)/net/ipsec
KERNELCRYPTODES=$(KERNELSRC)/crypto/ciphers/des
KERNELLIBFREESWAN=$(KERNELSRC)/lib/libfreeswan
KERNELLIBZLIB=$(KERNELSRC)/lib/zlib
KERNELLIBCRYPTO=$(KERNELSRC)/lib/libcrypto
KERNELINCLUDE=$(KERNELSRC)/include
KERNELALG=$(KERNELKLIPS)/alg

MAKEUTILS=packaging/utils
ERRCHECK=${MAKEUTILS}/errcheck
KVUTIL=${MAKEUTILS}/kernelversion
KVSHORTUTIL=${MAKEUTILS}/kernelversion-short

# kernel details
# what variant of our patches should we use, and where is it
KERNELREL=$(shell ${KVSHORTUTIL} ${KERNELSRC}/Makefile)

# directories visited by all recursion
SUBDIRS=doc lib programs linux

# declaration for make's benefit
.PHONY:	def insert kpatch klink klibcryptolink patches _patches _patches2.2 _patches2.4 \
	klipsdefaults programs install clean distclean \
	ogo oldgo menugo xgo \
	omod oldmod menumod xmod \
	pcf ocf mcf xcf rcf nopromptgo \
	precheck verset confcheck kernel module kinstall minstall \
	backup unpatch uinstall install_file_list \
	snapready relready ready buildready devready uml check taroldinstall \
	umluserland


# dummy default rule
def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

# everything that's necessary to put Klips into the kernel
insert:	patches klink klipsdefaults

kpatch: unapplypatch applypatch klipsdefaults

unapplypatch:
	-if [ -f ${KERNELSRC}/freeswan.patch ]; then \
		echo Undoing previous patches; \
		cat ${KERNELSRC}/freeswan.patch | (cd ${KERNELSRC} && patch -p1 -R --force -E -z .preipsec --reverse --ignore-whitespace ); \
	fi

applypatch:
	echo Now performing forward patches; 
	make kernelpatch${KERNELREL} | tee ${KERNELSRC}/freeswan.patch | (cd ${KERNELSRC} && patch -p1 -b -z .preipsec --forward --ignore-whitespace )

kdiff:
	echo Comparing ${KERNELSRC} to ${FREESWANSRCDIR}/linux.
	packaging/utils/kerneldiff ${KERNELSRC}

# create KERNELKLIPS and populate it with symlinks to the sources
klink:
	-[ -L $(KERNELKLIPS)/ipsec_init.c  ] && rm -rf ${KERNELKLIPS}
	-[ -L $(KERNELCRYPTODES)/cbc_enc.c ] && rm -rf ${KERNELCRYPTODES}
	-[ -L $(KERNELLIBFREESWAN)/subnettoa.c ] && rm -rf ${KERNELLIBFREESWAN}
	-[ -L ${KERNELLIBZLIB}/deflate.c   ] && rm -rf ${KERNELLIBZLIB}
	-[ -L ${KERNELINCLUDE}/freeswan.h  ] && for i in linux/include/*; do rm -f ${KERNELINCLUDE}/$$i; done
	-[ -L $(KERNELALG)/Makefile ] && rm -rf $(KERNELALG)
	-[ -L $(KERNELLIBCRYPTO) ] && rm -f $(KERNELLIBCRYPTO)
	mkdir -p $(KERNELKLIPS)
	mkdir -p $(KERNELCRYPTODES)
	mkdir -p $(KERNELLIBFREESWAN)
	mkdir -p $(KERNELLIBZLIB)
	mkdir -p $(KERNELALG)
	$(KLIPSLINK) `pwd`/Makefile.ver 	     $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/linux/include/*	     $(KERNELINCLUDE)
	$(KLIPSLINK) `pwd`/linux/net/ipsec/Makefile* $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/linux/net/ipsec/Config.in $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/linux/net/ipsec/defconfig $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/linux/net/ipsec/*.[ch]    $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/linux/net/ipsec/alg/Makefile*           $(KERNELALG)
	$(KLIPSLINK) `pwd`/linux/net/ipsec/alg/Config.*            $(KERNELALG)
	$(KLIPSLINK) `pwd`/linux/net/ipsec/alg/ipsec_alg*.[ch]     $(KERNELALG)
	$(KLIPSLINK) `pwd`/linux/net/ipsec/alg/scripts             $(KERNELALG)
	# Each ALGo does it own symlinks
	$(KLIPSLINK) `pwd`/lib/libcrypto             $(KERNELLIBCRYPTO)
	$(KLIPSLINK) `pwd`/linux/lib/zlib/*.[ch]     $(KERNELLIBZLIB)
	$(KLIPSLINK) `pwd`/linux/lib/zlib/Makefile*  $(KERNELLIBZLIB)
	$(KLIPSLINK) `pwd`/linux/lib/libfreeswan/*.[ch]    $(KERNELLIBFREESWAN)
	$(KLIPSLINK) `pwd`/linux/lib/libfreeswan/Makefile* $(KERNELLIBFREESWAN)
	$(KLIPSLINK) `pwd`/linux/crypto/ciphers/des/*.[chsS] $(KERNELCRYPTODES)
	$(KLIPSLINK) `pwd`/linux/crypto/ciphers/des/Makefile* $(KERNELCRYPTODES)
	sed '/"/s/xxx/$(IPSECVERSION)/' linux/lib/libfreeswan/version.in.c >$(KERNELKLIPS)/version.c

# create libcrypto symlink
klibcryptolink:
	-[ -L $(KERNELLIBCRYPTO) ] && rm -f $(KERNELLIBCRYPTO)
	$(KLIPSLINK) `pwd`/lib/libcrypto             $(KERNELLIBCRYPTO)

# patch kernel
PATCHER=packaging/utils/patcher

patches:
	@echo \"make patches\" is obsolete. See \"make kpatch\".
	exit 1

_patches:
	echo "===============" >>out.kpatch
	echo "`date` `cd $(KERNELSRC) ; pwd`" >>out.kpatch
	$(MAKE) __patches$(KERNELREL) >>out.kpatch

# Linux-2.0.x version
__patches __patches2.0:
	@$(PATCHER) -v $(KERNELSRC) Documentation/Configure.help \
	  'CONFIG_IPSEC' $(PATCHES)/Documentation/Configure.help.fs2_0.patch
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
	  'CONFIG_IPSEC' $(PATCHES)/net/Config.in.fs2_0.patch
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
	  'CONFIG_IPSEC' $(PATCHES)/net/Makefile.fs2_0.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
	  'CONFIG_IPSEC' $(PATCHES)/net/ipv4/af_inet.c.fs2_0.patch
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink.c
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# Linux-2.2.x version
PATCHES24=klips/patches2.3
__patches2.2:
	@$(PATCHER) -v -c $(KERNELSRC) Documentation/Configure.help \
	  'CONFIG_IPSEC' $(PATCHES)/Documentation/Configure.help.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_IPSEC' $(PATCHES)/net/Config.in.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_IPSEC' $(PATCHES)/net/Makefile.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_IPSEC' $(PATCHES)/net/ipv4/af_inet.c.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/udp.c \
		'CONFIG_IPSEC' $(PATCHES)/net/ipv4/udp.c.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) include/net/sock.h \
		'CONFIG_IPSEC' $(PATCHES)/net/include.net.sock.h.fs2_2.patch
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/netlink.h
	@$(PATCHER) -v $(KERNELSRC) net/netlink/af_netlink.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink/netlink_dev.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/socket.h
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# Linux-2.4.0 version
PATCHES22=klips/patches2.2
__patches2.3 __patches2.4:
	@$(PATCHER) -v -c $(KERNELSRC) Documentation/Configure.help \
		'CONFIG_IPSEC' $(PATCHES)/Documentation/Configure.help.fs2_2.patch
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_IPSEC' $(PATCHES)/net/Config.in.fs2_4.patch
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_IPSEC' $(PATCHES)/net/Makefile.fs2_4.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_IPSEC' $(PATCHES)/net/ipv4/af_inet.c.fs2_4.patch
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/udp.c \
		'CONFIG_IPSEC' $(PATCHES)/net/ipv4/udp.c.fs2_4.patch
	@$(PATCHER) -v $(KERNELSRC) include/net/sock.h \
		'CONFIG_IPSEC' $(PATCHES)/net/include.net.sock.h.fs2_4.patch
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/netlink.h
	@$(PATCHER) -v $(KERNELSRC) net/netlink/af_netlink.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink/netlink_dev.c
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

klipsdefaults:
	@KERNELDEFCONFIG=$(KERNELSRC)/arch/$(ARCH)/defconfig ; \
	KERNELCONFIG=$(KCFILE) ; \
	if ! egrep -q 'CONFIG_IPSEC' $$KERNELDEFCONFIG ; \
	then \
		set -x ; \
		cp -a $$KERNELDEFCONFIG $$KERNELDEFCONFIG.orig ; \
		chmod u+w $$KERNELDEFCONFIG ; \
		cat $$KERNELDEFCONFIG $(KERNELKLIPS)/defconfig \
			>$$KERNELDEFCONFIG.tmp ; \
		rm -f $$KERNELDEFCONFIG ; \
		cp -a $$KERNELDEFCONFIG.tmp $$KERNELDEFCONFIG ; \
		rm -f $$KERNELDEFCONFIG.tmp ; \
	fi ; \
	if ! egrep -q 'CONFIG_IPSEC' $$KERNELCONFIG ; \
	then \
		set -x ; \
		cp -a $$KERNELCONFIG $$KERNELCONFIG.orig ; \
		chmod u+w $$KERNELCONFIG ; \
		cat $$KERNELCONFIG $(KERNELKLIPS)/defconfig \
			>$$KERNELCONFIG.tmp ; \
		rm -f $$KERNELCONFIG ; \
		cp -a $$KERNELCONFIG.tmp $$KERNELCONFIG ; \
		rm -f $$KERNELCONFIG.tmp ; \
	fi



# programs

checkv199install:
	if [ -f ${LIBDIR}/pluto ]; \
	then \
		echo WARNING: FreeS/WAN 1.99 still installed. ;\
		echo WARNING: moving ${LIBDIR} to ${LIBDIR}.v1 ;\
		mv ${LIBDIR} ${LIBDIR}.v1 ;\
	fi

install:: checkv199install

programs install clean checkprograms::
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) FREESWANSRCDIR=.. $@ ) || exit 1; \
	done; \

clean::
	rm -rf $(RPMTMPDIR) $(RPMDEST)
	rm -f out.*build out.*install	# but leave out.kpatch
	rm -f rpm.spec

distclean:	clean
	rm -f out.kpatch 
	if [ -f umlsetup.sh ]; then source umlsetup.sh; if [ -d "$$POOLSPACE" ]; then rm -rf $$POOLSPACE; fi; fi



# proxies for major kernel make operations

# do-everything entries
KINSERT_PRE=precheck verset insert
PRE=precheck verset kpatch klibcryptolink
POST=confcheck programs kernel install 
MPOST=confcheck programs module install 
ogo:		$(PRE) pcf $(POST)
oldgo:		$(PRE) ocf $(POST)
nopromptgo:	$(PRE) rcf $(POST)
menugo:		$(PRE) mcf $(POST)
xgo:		$(PRE) xcf $(POST)
omod:		$(PRE) pcf $(MPOST)
oldmod:		$(PRE) ocf $(MPOST)
menumod:	$(PRE) mcf $(MPOST)
xmod:		$(PRE) xcf $(MPOST) 

# preliminaries
precheck:
	@if test ! -d $(KERNELSRC) -a ! -L $(KERNELSRC) ; \
	then \
		echo '*** cannot find directory "$(KERNELSRC)"!!' ; \
		echo '*** may be necessary to add symlink to kernel source' ; \
		exit 1 ; \
	fi
	@if ! cd $(KERNELSRC) ; \
	then \
		echo '*** cannot "cd $(KERNELSRC)"!!' ; \
		echo '*** may be necessary to add symlink to kernel source' ; \
		exit 1 ; \
	fi
	@if test ! -f $(KCFILE) ; \
	then \
		echo '*** cannot find "$(KCFILE)"!!' ; \
		echo '*** perhaps kernel has never been configured?' ; \
		echo '*** please do that first; the results are necessary.' ; \
		exit 1 ; \
	fi
	@if test ! -f $(VERFILE) ; \
	then \
		echo '*** cannot find "$(VERFILE)"!!' ; \
		echo '*** perhaps kernel has never been compiled?' ; \
		echo '*** please do that first; the results are necessary.' ; \
		exit 1 ; \
	fi

# set version code if this is a fresh CVS checkout
ifeq ($(wildcard cvs.datemark),cvs.datemark)
verset Makefile.ver: cvs.datemark
	echo IPSECVERSION=`date -r cvs.datemark +cvs%Y%b%d_%H:%M:%S` >Makefile.ver 
	rm -f cvs.datemark; 
else
verset Makefile.ver: 
	@grep IPSECVERSION Makefile.ver
endif

Makefile: Makefile.ver

# configuring (exit statuses disregarded, something fishy here sometimes)
xcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) xconfig
mcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) menuconfig
pcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) config

ocf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) oldconfig 

rcf:
	cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) oldconfig_nonint </dev/null
	cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) dep >/dev/null

confcheck:
	@if test ! -f $(KCFILE) ; \
	then echo '*** no kernel configuration file written!!' ; exit 1 ; \
	fi
	@if ! egrep -q '^CONFIG_IPSEC=[my]' $(KCFILE) ; \
	then echo '*** IPsec not in kernel config ($(KCFILE))!!' ; exit 1 ; \
	fi
	@if ! egrep -q 'CONFIG_IPSEC[ 	]+1' $(ACFILE) && \
		! egrep -q 'CONFIG_IPSEC_MODULE[ 	]+1' $(ACFILE) ; \
	then echo '*** IPsec in kernel config ($(KCFILE)),' ; \
		echo '***	but not in config header file ($(ACFILE))!!' ; \
		exit 1 ; \
	fi
	@if egrep -q '^CONFIG_IPSEC=m' $(KCFILE) && \
		! egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then echo '*** IPsec configured as module in kernel with no module support!!' ; exit 1 ; \
	fi
	@if ! egrep -q 'CONFIG_IPSEC_AH[ 	]+1' $(ACFILE) && \
		! egrep -q 'CONFIG_IPSEC_ESP[ 	]+1' $(ACFILE) ; \
	then echo '*** IPsec configuration must include AH or ESP!!' ; exit 1 ; \
	fi

# kernel building, with error checks
kernel:
	rm -f out.kbuild out.kinstall
	# undocumented kernel folklore: clean BEFORE dep. 
	# we run make dep seperately, because there is no point in running ERRCHECK
	# on the make dep output.
	# see LKML thread "clean before or after dep?"
	( cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) $(KERNCLEAN) $(KERNDEP) )
	( cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) $(KERNEL) ) 2>&1 | tee out.kbuild
	@if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then set -x ; \
		( cd $(KERNELSRC) ; \
		$(MAKE) $(KERNMAKEOPTS) modules 2>&1 ) | tee -a out.kbuild ; \
	fi
	${ERRCHECK} out.kbuild

# this target takes a kernel source tree and it builds a link tree,
# and then does make oldconfig for each .config file that was found in configs.
# The location for the disk space required for the link tree is found via
# $RH_KERNELSRC_POOL
preprhkern4module:
	if [ -z "${RH_KERNELSRC_POOL}" ]; then echo Please set RH_KERNELSRC_POOL.; exit 1; fi
	mkdir -p ${RH_KERNELSRC_POOL}
	KV=`${KVUTIL} $(RH_KERNELSRC)/Makefile` ; \
	cd ${RH_KERNELSRC_POOL} && \
	mkdir -p $$KV && cd $$KV && \
	for config in ${RH_KERNELSRC}/configs/*; do \
		basecfg=`basename $$config` ;\
		mkdir -p ${RH_KERNELSRC_POOL}/$$KV/$$basecfg && \
		cd ${RH_KERNELSRC_POOL}/$$KV/$$basecfg && \
		lndir ${RH_KERNELSRC} . && \
		rm -rf include/asm && \
		(cd include/linux && sed -e '/#include "\/boot\/kernel.h"/d' <rhconfig.h >rhconfig.h-new && mv rhconfig.h-new rhconfig.h ) && \
		rm -f include/linux/modules/*.stamp && \
		make dep && \
		make oldconfig; \
	done;

# module-only building, with error checks
ifneq ($(strip $(MODBUILDDIR)),)
${MODBUILDDIR}/Makefile : ${FREESWANSRCDIR}/packaging/makefiles/module.make
	mkdir -p ${MODBUILDDIR}
	cp ${FREESWANSRCDIR}/packaging/makefiles/module.make ${MODBUILDDIR}/Makefile
	echo "# "                        >>${MODBUILDDIR}/Makefile
	echo "# Local Variables: "       >>${MODBUILDDIR}/Makefile
	echo "# compile-command: \"${MAKE} FREESWANSRCDIR=${FREESWANSRCDIR} ARCH=${ARCH} ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} ipsec.o\""         >>${MODBUILDDIR}/Makefile
	echo "# End: "       >>${MODBUILDDIR}/Makefile

# clean out the linux/net/ipsec directory so that VPATH will work properly
module: ${MODBUILDDIR}/Makefile
	${MAKE} -C linux/net/ipsec ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} clean
	${MAKE} -C ${MODBUILDDIR}  ARCH=${ARCH} ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} ipsec.o
	${MAKE} -C ${MODBUILDDIR}  ARCH=${ARCH} ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} LIBCRYPTO=${FREESWANSRCDIR}/lib/libcrypto MODULE_FLAGS="$(MODULE_FLAGS)" alg_modules

modclean: ${MODBUILDDIR}/Makefile
	${MAKE} -C ${MODBUILDDIR} clean

# module-only install, with error checks
minstall:
	( FSMODLIB=`make -C $(KERNELSRC) -p dummy | ( sed -n -e '/^MODLIB/p' -e '/^MODLIB/q' ; cat > /dev/null ) | sed -e 's/^MODLIB[ :=]*\([^;]*\).*/\1/'` ; \
	if [ -z "$$FSMODLIB" ] ; then \
		FSMODLIB=`make -C $(KERNELSRC) -n -p modules_install | ( sed -n -e '/^MODLIB/p' -e '/^MODLIB/q' ; cat > /dev/null ) | sed -e 's/^MODLIB[ :=]*\([^;]*\).*/\1/'` ; \
	fi ; \
	if [ -z "$$FSMODLIB" ] ; then \
		echo "No known place to install module. Aborting." ; \
		exit 93 ; \
	fi ; \
	set -x ; \
	mkdir -p $$FSMODLIB/kernel/net/ipsec ; \
	cp $(MODBUILDDIR)/ipsec.o $$FSMODLIB/kernel/net/ipsec ; \
	mkdir -p $$FSMODLIB/kernel/net/ipsec/alg ; \
	for i in `sed -n '/IPSEC_ALG/s/CONFIG_IPSEC_ALG_\(.*\)=[Mm]/ipsec_\1.o/p' $(KCFILE) | tr '[A-Z]' '[a-z]'`;do \
		echo "installing $$i"; \
		cp $(MODBUILDDIR)/alg/$$i $$FSMODLIB/kernel/net/ipsec/alg ;\
	done )

else
module: 
	${MAKE} -C linux/net/ipsec ARCH=${ARCH} ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} ipsec.o
	${MAKE} -C linux/net/ipsec ARCH=${ARCH} ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} LIBCRYPTO=${FREESWANSRCDIR}/lib/libcrypto MODULE_FLAGS="$(MODULE_FLAGS)" alg_modules

modclean:
	${MAKE} -C linux/net/ipsec ARCH=${ARCH} ${MODULE_FLAGS} MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} clean

# module-only install, with error checks
minstall:
	( FSMODLIB=`make -C $(KERNELSRC) -p dummy | ( sed -n -e '/^MODLIB/p' -e '/^MODLIB/q' ; cat > /dev/null ) | sed -e 's/^MODLIB[ :=]*\([^;]*\).*/\1/'` ; \
	if [ -z "$$FSMODLIB" ] ; then \
		FSMODLIB=`make -C $(KERNELSRC) -n -p modules_install | ( sed -n -e '/^MODLIB/p' -e '/^MODLIB/q' ; cat > /dev/null ) | sed -e 's/^MODLIB[ :=]*\([^;]*\).*/\1/'` ; \
	fi ; \
	if [ -z "$$FSMODLIB" ] ; then \
		echo "No known place to install module. Aborting." ; \
		exit 93 ; \
	fi ; \
	set -x ; \
	mkdir -p $$FSMODLIB/kernel/net/ipsec ; \
	cp linux/net/ipsec/ipsec.o $$FSMODLIB/kernel/net/ipsec ; \
	mkdir -p $$FSMODLIB/kernel/net/ipsec/alg ; \
	for i in `sed -n '/IPSEC_ALG/s/CONFIG_IPSEC_ALG_\(.*\)=[Mm]/ipsec_\1.o/p' $(KCFILE) | tr '[A-Z]' '[a-z]'`;do \
		echo "installing $$i"; \
		cp linux/net/ipsec/alg/$$i $$FSMODLIB/kernel/net/ipsec/alg ;\
	done )

endif

# kernel install, with error checks
kinstall:
	rm -f out.kinstall
	>out.kinstall
	# undocumented kernel folklore: modules_install must precede install (observed on RHL8.0)
	@if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then set -x ; \
		( cd $(KERNELSRC) ; \
		$(MAKE) $(KERNMAKEOPTS) modules_install 2>&1 ) | tee -a out.kinstall ; \
	fi
	( cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) install ) 2>&1 | tee -a out.kinstall
	${ERRCHECK} out.kinstall

kernelpatch2.5:
	packaging/utils/kernelpatch 2.5

kernelpatch2.4 kernelpatch:
	packaging/utils/kernelpatch 2.4

kernelpatch2.2:
	packaging/utils/kernelpatch 2.2

kernelpatch2.0:
	packaging/utils/kernelpatch 2.0

install_file_list:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) --no-print-directory FREESWANSRCDIR=.. install_file_list ) || exit 1; \
	done; 

# take all the patches out of the kernel
# (Note, a couple of files are modified by non-patch means; they are
# included in "make backup".)
unpatch:
	@echo \"make unpatch\" is obsolete. See make unapplypatch.
	exit 1

_unpatch:
	for f in `find $(KERNELSRC)/. -name '*.preipsec' -print` ; \
	do \
		echo "restoring $$f:" ; \
		dir=`dirname $$f` ; \
		core=`basename $$f .preipsec` ; \
		cd $$dir ; \
		mv -f $$core.preipsec $$core ; \
		rm -f $$core.wipsec $$core.ipsecmd5 ; \
	done

# uninstall, as much as possible
uninstall:
	$(MAKE) --no-print-directory install_file_list | egrep -v '(/ipsec.conf$$|/ipsec.d/)' | xargs rm -f

taroldinstall:
	tar --ignore-failed-read -c -z -f oldFreeSWAN.tar.gz `$(MAKE) --no-print-directory install_file_list`

# some oddities meant for the developers, probably of no use to users

# make tags and TAGS files from ctags and etags for vi and emacs, respectively.
tags TAGS: dummy
	etags `find lib programs linux -name '*.[ch]'`
	ctags `find lib programs linux -name '*.[ch]'`

dummy:

# at the moment there is no difference between snapshot and release build
snapready:	buildready
relready:	buildready
ready:		devready

# set up for build
buildready:
	rm -f dtrmakefile cvs.datemark
	cd doc ; $(MAKE) -s

uml:	programs checkprograms
	@echo XXX do some checks to see if all the manual pieces are done.
	-chmod +x testing/utils/make-uml.sh
	testing/utils/make-uml.sh `pwd`

umluserland:
	(touch Makefile.inc && source umlsetup.sh && cd $$POOLSPACE && make $$FREESWANHOSTS $$REGULARHOSTS ) 


# DESTDIR is normally set in Makefile.inc
# These recipes explicitly pass it to the second-level makes so that
# DESTDIR can be adjusted for building for UML without changing Makefile.inc
# See	testing/utils/functions.sh
#	testing/utils/make-uml.sh
#	testing/utils/uml-functions.sh
check:	uml Makefile.ver
ifneq ($(strip(${REGRESSRESULTS})),)
	mkdir -p ${REGRESSRESULTS}
endif
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) DESTDIR=${DESTDIR} checkprograms || exit 1); done
	@for d in $(SUBDIRS); \
	do \
		echo ===================================; \
		echo Now making check in $$d; \
		echo ===================================; \
		(cd $$d && $(MAKE) DESTDIR=${DESTDIR} check || exit 1);\
	done
ifneq ($(strip(${REGRESSRESULTS})),)
	-perl testing/utils/regress-summarize-results.pl ${REGRESSRESULTS}
endif


rpm:
	@echo please cd packaging/redhat and
	@echo run "make RH_KERNELSRC=/some/path/to/kernel/src rpm"

ipkg_strip:
	@echo "Minimizing size for ipkg binaries..."
	@cd $(DESTDIR)$(INC_USRLOCAL)/lib/ipsec && \
	for f in *; do (if file $$f | grep ARM > /dev/null; then ( $(STRIP) --strip-unneeded $$f); fi); done
	@rm -r $(DESTDIR)$(INC_USRLOCAL)/man
	@rm -f $(DESTDIR)$(INC_RCDEFAULT)/*.old
	@rm -f $(DESTDIR)$(INC_USRLOCAL)/lib/ipsec/*.old
	@rm -f $(DESTDIR)$(INC_USRLOCAL)/libexec/ipsec/*.old
	@rm -f $(DESTDIR)$(INC_USRLOCAL)/sbin/*.old

ipkg_module:
	@echo "Moving ipsec.o into temporary location..."
	KV=$(shell ${KVUTIL} ${KERNELSRC}/Makefile) && \
	mkdir -p $(FREESWANSRCDIR)/packaging/ipkg/kernel-module/lib/modules/$$KV/net/ipsec
	KV=$(shell ${KVUTIL} ${KERNELSRC}/Makefile) && \
	cp linux/net/ipsec/ipsec.o $(FREESWANSRCDIR)/packaging/ipkg/kernel-module/lib/modules/$$KV/net/ipsec/
	KV=$(shell ${KVUTIL} ${KERNELSRC}/Makefile)

ipkg_clean:
	rm -rf $(FREESWANSRCDIR)/packaging/ipkg/kernel-module/
	rm -rf $(FREESWANSRCDIR)/packaging/ipkg/ipkg/
	rm -f $(FREESWANSRCDIR)/packaging/ipkg/control-freeswan
	rm -f $(FREESWANSRCDIR)/packaging/ipkg/control-freeswan-module


ipkg: programs install ipkg_strip ipkg_module
	@echo "Generating ipkg..."; 
	DESTDIR=${DESTDIR} FREESWANSRCDIR=${FREESWANSRCDIR} ARCH=${ARCH} IPSECVERSION=${IPSECVERSION} ./packaging/ipkg/generate-ipkg




