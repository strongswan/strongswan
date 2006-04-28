# Makefile for KLIPS kernel code as a module
# Copyright (C) 1998, 1999, 2000,2001  Richard Guy Briggs.
# Copyright (C) 2002	Michael Richardson <mcr@freeswan.org>
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
# RCSID $Id: Makefile,v 1.2 2004/03/22 21:53:19 as Exp $
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#

ifeq ($(strip $(KLIPSMODULE)),)
FREESWANSRCDIR=.
else
FREESWANSRCDIR=../../..
endif
-include ${FREESWANSRCDIR}/Makefile.ver

ifeq ($(strip $(KLIPS_TOP)),)
KLIPS_TOP=../..
endif

ifneq ($(strip $(KLIPSMODULE)),)

ifndef TOPDIR
TOPDIR:=/usr/src/linux
endif
export TOPDIR

endif

#
# This magic from User-Mode-Linux list. It gets list of -I options, as
# UML needs some extra, that varry by revision.
#
KERNEL_CFLAGS= $(shell $(MAKE) -C $(TOPDIR) --no-print-directory -s -f Makefile ARCH=$(ARCH) MAKEFLAGS= script SCRIPT='@echo $$(CFLAGS)'   )

MODULE_CFLAGS= $(shell $(MAKE) -C $(TOPDIR) --no-print-directory -s -f Makefile ARCH=$(ARCH) MAKEFLAGS= script SCRIPT='@echo $$(MODFLAGS)'  )

subdir-  := 
subdir-n := 
subdir-y :=
subdir-m :=


MOD_DESTDIR:=net/ipsec

export TOPDIR

all: ipsec.o

foo:
	echo KERNEL: ${KERNEL_CFLAGS}
	echo MODULE: ${MODULE_CFLAGS}

ipsec.o: foo

O_TARGET := ipsec.o
obj-y := ipsec_init.o ipsec_sa.o ipsec_radij.o radij.o
obj-y += ipsec_life.o ipsec_proc.o
obj-y += ipsec_tunnel.o ipsec_xmit.o ipsec_rcv.o
obj-y += sysctl_net_ipsec.o 
obj-y += pfkey_v2.o pfkey_v2_parser.o pfkey_v2_ext_process.o
#obj-y += version.o

LIBDESDIR=${KLIPS_TOP}/crypto/ciphers/des
VPATH+= ${LIBDESDIR}

include ${LIBDESDIR}/Makefile.objs

LIBFREESWANDIR=${KLIPS_TOP}/lib/libfreeswan
VPATH+=${LIBFREESWANDIR}

include ${LIBFREESWANDIR}/Makefile.objs

# IPcomp stuff
obj-$(CONFIG_IPSEC_IPCOMP) += ipcomp.o 

LIBZLIBSRCDIR=${KLIPS_TOP}/lib/zlib
VPATH+=${LIBZLIBSRCDIR}

# LIBCRYPTO Will be overriden eg. when doing  "make module" 
# from freeswan-2 src root
# Default value assumes already symlinked libcrypto under $TOPDIR/lib
LIBCRYPTO=$(TOPDIR)/lib/libcrypto
VPATH+=${LIBCRYPTO}

alg/static_init_mod.o: dummy
	$(MAKE) -C alg CC='$(CC)' TOPDIR='$(TOPDIR)' \
	'EXTRA_CFLAGS=$(EXTRA_CFLAGS)' \
	static_init_mod.o


alg_modules: dummy
	$(MAKE) $(MODULE_FLAGS) -C alg CC='$(CC)' TOPDIR='$(TOPDIR)' \
	'LIBCRYPTO=$(LIBCRYPTO)' \
	'EXTRA_CFLAGS=$(EXTRA_CFLAGS)' \
	modules

#	CFLAGS='$(CFLAGS)' \
#	MODULE_CFLAGS='$(MODULE_CFLAGS)' KERNEL_CFLAGS='$(KERNEL_CFLAGS)' \
#
include ${LIBZLIBSRCDIR}/Makefile.objs

export-objs := radij.o

# New handling of KERNEL_CFLAGS and MODULE_CFLAGS introduced in 2.0
# tosses export-objs logic :(
CFLAGS_ipsec_alg.o += -DEXPORT_SYMTAB
obj-$(CONFIG_IPSEC_ALG) +=ipsec_alg.o alg/static_init_mod.o
export-objs += ipsec_alg.o
subdir-m += alg

EXTRA_CFLAGS += $(ALGO_FLAGS)


# include file with .h-style macros that would otherwise be created by
# config. Must occur before other includes.
ifneq ($(strip $(MODULE_DEF_INCLUDE)),)
EXTRA_CFLAGS += -include ${MODULE_DEF_INCLUDE}
endif

# 'override CFLAGS' should really be 'EXTRA_CFLAGS'
#EXTRA_CFLAGS += -nostdinc
EXTRA_CFLAGS += -I${KLIPS_TOP}/include

EXTRA_CFLAGS += -I${TOPDIR}/include 
EXTRA_CFLAGS += -I${LIBZLIBSRCDIR}

ifeq ($(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION),2.4.2-2)
EXTRA_CFLAGS += -DREDHAT_BOGOSITY
endif

ifeq ($(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION),2.4.3-12)
EXTRA_CFLAGS += -DREDHAT_BOGOSITY
endif


#ifeq ($(CONFIG_IPSEC_DEBUG),y)
#EXTRA_CFLAGS += -g
#endif

#ifeq ($(CONFIG_IPSEC_ALG), y)
EXTRA_CFLAGS += -DCONFIG_IPSEC_ALG
#endif
# MOST of these flags are in KERNEL_CFLAGS already!

EXTRA_CFLAGS += $(KLIPSCOMPILE)
EXTRA_CFLAGS += -Wall
#EXTRA_CFLAGS += -Werror
#EXTRA_CFLAGS += -Wconversion 
#EXTRA_CFLAGS += -Wmissing-prototypes 
# cannot use both -Wpointer-arith and -Werror with CONFIG_HIGHMEM
# include/linux/highmem.h has an inline function definition that uses void* arithmentic.
ifeq ($(CONFIG_NOHIGHMEM),y)
EXTRA_CFLAGS += -Wpointer-arith 
endif
#EXTRA_CFLAGS += -Wcast-qual 
#EXTRA_CFLAGS += -Wmissing-declarations 
#EXTRA_CFLAGS += -Wstrict-prototypes
#EXTRA_CFLAGS += -pedantic
#EXTRA_CFLAGS += -O3
#EXTRA_CFLAGS += -W
#EXTRA_CFLAGS += -Wwrite-strings 
#EXTRA_CFLAGS += -Wbad-function-cast 

ifneq ($(strip $(KLIPSMODULE)),)
# for when we aren't building in the kernel tree
EXTRA_CFLAGS += -DARCH=${ARCH} 
EXTRA_CFLAGS += -DMODVERSIONS
EXTRA_CFLAGS += -include ${TOPDIR}/include/linux/modversions.h
EXTRA_CFLAGS += ${MODULE_CFLAGS} 
endif

EXTRA_CFLAGS += ${KERNEL_CFLAGS}


# GCC 3.2 (and we presume any other 3.x) wants -falign-functions
# in place of the traditional -malign-functions.  Getting this
# wrong leads to a warning, which is fatal due to our use of -Werror.
ifeq ($(patsubst 3.%,3,$(shell $(CC) -dumpversion)),3)
override CFLAGS:=$(subst -malign-functions=,-falign-functions=,$(CFLAGS))
endif


obj-$(CONFIG_IPSEC_AUTH_HMAC_MD5) += ipsec_md5c.o
obj-$(CONFIG_IPSEC_AUTH_HMAC_SHA1) += ipsec_sha1.o

###
### Pre Rules.make
###
# undo O_TARGET, obj-y if no static
ifneq ($(CONFIG_IPSEC),y)
O_TARGET := 
ipsec_obj-y := $(obj-y)
obj-y :=
subdir-y :=
endif

# Define obj-m if modular ipsec 
ifeq ($(CONFIG_IPSEC),m)
obj-m += ipsec.o
endif


# These rules translate from new to old makefile rules
# Translate to Rules.make lists.
multi-used      := $(filter $(list-multi), $(obj-y) $(obj-m))
multi-objs      := $(foreach m, $(multi-used), $($(basename $(m))-objs))
active-objs     := $(sort $(multi-objs) $(obj-y) $(obj-m))
O_OBJS          := $(obj-y)
M_OBJS          := $(obj-m)
MIX_OBJS        := $(filter $(export-objs), $(active-objs))
OX_OBJS := $(export-objs)
SUB_DIRS := $(subdir-y)
ALL_SUB_DIRS := $(subdir-y) $(subdir-m)
MOD_SUB_DIRS := $(subdir-m)

#   dunno why, but some 2.2 setups may need explicit -DEXPORT_SYMTAB
#   uncomment next line if ipsec_alg.c compilation fails with
#   "parse error before `EXPORT_SYMTAB_not_defined'"  --Juanjo
# CFLAGS_ipsec_alg.o += -DEXPORT_SYMTAB
#

include $(TOPDIR)/Rules.make

###
### Post Rules.make
###
# for modular ipsec, no O_TARGET defined => define ipsec.o creation rules
ifeq ($(CONFIG_IPSEC),m)
ipsec.o : $(ipsec_obj-y)
	rm -f $@
	$(LD) $(LD_EXTRAFLAGS) -r $(ipsec_obj-y) -o $@
endif

$(ipsec_obj-y) $(obj-y) $(obj-m):  $(TOPDIR)/include/linux/config.h $(TOPDIR)/include/linux/autoconf.h

#$(obj-y) $(obj-m):  $(TOPDIR)/include/linux/config.h $(TOPDIR)/include/linux/autoconf.h

USE_STANDARD_AS_RULE=true

clean:
	$(MAKE) -C alg clean
	-rm -f *.o
	-rm -f .*.o.flags
	-rm version.c

tags TAGS: *.c *.h libfreeswan/*.c libfreeswan/*.h
	etags *.c ../../include/*.h ../../include/freeswan/*.h
	ctags *.c ../../include/*.h ../../include/freeswan/*.h

tar:
		tar -cvf /dev/f1 .

#
# $Log: Makefile,v $
# Revision 1.2  2004/03/22 21:53:19  as
# merged alg-0.8.1 branch with HEAD
#
# Revision 1.1.4.1  2004/03/16 09:48:19  as
# alg-0.8.1rc12 patch merged
#
# Revision 1.1  2004/03/15 20:35:26  as
# added files from freeswan-2.04-x509-1.5.3
#
# Revision 1.61  2003/06/22 21:07:46  mcr
# 	adjusted TAGS target in makefile to be useful in 2.00 source layout.
#
# Revision 1.60  2003/05/03 23:45:23  mcr
# 	rm .o.flags and generated version.c file.
#
# Revision 1.59  2003/02/12 19:32:47  rgb
# Added ipsec_xmit to the list of object files.
#
# Revision 1.58  2003/01/03 00:36:44  rgb
#
# Added emacs compile-command.
#
# Revision 1.57  2002/11/08 23:49:53  mcr
# 	use KERNEL_CFLAGS and MODULE_CFLAGS to get proper list
# 	of include directories.
# 	This also eliminates some of the guesswork in the kernel
# 	configuration file.
#
# Revision 1.56  2002/11/08 23:23:18  mcr
# 	attempt to guess kernel compilation flags (i.e. list of -I)
# 	by using some magic targets in the kernel makefile.
#
# Revision 1.55  2002/11/08 10:13:33  mcr
# 	added additional include directories for module builds for 2.4.19.
#
# Revision 1.54  2002/10/20 06:10:30  build
# CONFIG_NOHIGHMEM for -Wpointer-arith RPM building issues.
#
# Revision 1.53  2002/10/17 16:32:01  mcr
# 	enable standard AS rules.
#
# Revision 1.52  2002/10/06 06:13:44  sam
# Altering order of includes, so that architecture-specific header files,
# used for building RPM modules specifically, are processed first.
#
# Revision 1.51  2002/10/05 15:06:38  dhr
#
# - To allow for gcc3.2 (used in Red Hat Linux 8.0):  adjust CFLAGS (set
#   by kernel machinery) to use -falign-functions= in place of
#   -malign-functions=.  Eliminates a warning (fatal with -Werror).
#
# - When CONFIG_HIGHMEM is on, -Wpointer-arith will warn about
#   include/linux/highmem.h.  Since this is fatal with -Werror, we
#   suppress -Wpointer-arith if CONFIG_HIGHMEM is set.
#
# Revision 1.50  2002/09/16 21:19:45  mcr
# 	enable -Werror for production - this helps a lot (found a bug in ipsec_rcv.c)
#
# Revision 1.49  2002/07/29 05:12:39  mcr
# 	get rid of some extraneous stuff, now handled by a prefix
# 	Makefile when building as a module.
#
# Revision 1.48  2002/07/28 23:13:49  mcr
# 	set KLIPS_TOP and use it instead of ../..
# 	if KLIPSMODULE, then include a bunch of stuff defined in Makefile.inc
# 	that gets us the "typical" configuration that we want.
#
# Revision 1.47  2002/06/02 21:51:41  mcr
# 	changed TOPDIR->FREESWANSRCDIR in all Makefiles.
# 	(note that linux/net/ipsec/Makefile uses TOPDIR because this is the
# 	kernel sense.)
#
# Revision 1.46  2002/05/14 02:35:51  rgb
# Added file pfkey_v2_ext_process.c.
#
# Revision 1.45  2002/05/13 17:21:40  mcr
# 	mkdep dies when given a -I to a directory that does not exist.
# 	arch/${ARCH}/include is for UM arch only, so include it for that
# 	ARCH only.
#
# Revision 1.44  2002/04/24 20:38:12  mcr
# 	moved more stuff behind $KLIPSMODULE=y to get static linking to work.
#
# Revision 1.43  2002/04/24 09:16:18  mcr
# 	include local Makefile.ver as well as FS_rootdir version.
#
# Revision 1.42  2002/04/24 08:50:08  mcr
# 	critical patch is to set TOPDIR with :=.
#
# Revision 1.40  2002/04/24 00:41:07  mcr
# Moved from ./klips/net/ipsec/Makefile,v
#
# Revision 1.39  2002/01/17 04:39:40  rgb
# Take compile options from top level Makefile.inc
#
# Revision 1.38  2001/11/27 05:28:07  rgb
# Shut off -Werror until we figure out a graceful way of quieting down the
# pfkey_ops defined but not used complaint in the case of SMP in
# pfkey_v2.c.
#
# Revision 1.37  2001/11/27 05:10:15  rgb
# Added -Ilibdes and removed lib/des* symlinks.
#
# Revision 1.36  2001/11/26 09:23:47  rgb
# Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
#
# Revision 1.35.2.1  2001/09/25 02:17:50  mcr
# 	added ipsec_sa, ipsec_life, ipsec_proc.
# 	added -Werror to compile flags (see fix for zlib/zutil.h)
#
# Revision 1.3  2001/09/21 04:41:26  mcr
# 	actually, ipsec_proc.c and ipsec_life.c were never actually compiled.
#
# Revision 1.2  2001/09/21 04:11:33  mcr
# 	first compilable version.
#
# Revision 1.1.1.2  2001/09/17 01:17:52  mcr
#   snapshot 2001-09-16
#
# Revision 1.35  2001/09/07 22:09:12  rgb
# Quiet down compilation.
#
# Revision 1.34  2001/08/11 17:10:23  henry
# update bogosity stuff to cover RH7.1 update
#
# Revision 1.33  2001/06/14 19:35:07  rgb
# Update copyright date.
#
# Revision 1.32  2001/06/13 21:00:50  rgb
# Added a kludge to get around RedHat kernel version bogosity...
#
# Revision 1.31  2001/01/29 22:19:06  rgb
# Convert to 2.4 new style with back compat.
#
# Revision 1.30  2000/09/29 19:51:57  rgb
# Moved klips/net/ipsec/ipcomp_* to zlib/* (Svenning).
#
# Revision 1.29  2000/09/15 11:37:01  rgb
# Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
# IPCOMP zlib deflate code.
#
# Revision 1.28  2000/09/15 04:55:25  rgb
# Clean up pfkey object inclusion into the default object.
#
# Revision 1.27  2000/09/12 03:20:47  rgb
# Cleared out now unused pfkeyv2 switch.
# Enabled sysctl.
#
# Revision 1.26  2000/09/08 19:12:55  rgb
# Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
#
# Revision 1.25  2000/06/16 03:09:16  rgb
# Shut up cast lost warning due to changes in 2.4.0-test1.
#
# Revision 1.24  2000/03/16 06:40:48  rgb
# Hardcode PF_KEYv2 support.
#
# Revision 1.23  2000/02/14 21:10:38  rgb
# Added gcc debug flag when KLIPS_DEBUG is swtiched on.
#
# Revision 1.22  2000/01/21 09:44:29  rgb
# Added compiler switches to be a lot more fussy.
#
# Revision 1.21  1999/11/25 23:35:20  rgb
# Removed quotes to fix Alpha compile issues.
#
# Revision 1.20  1999/11/17 15:49:34  rgb
# Changed all occurrences of ../../../lib in pathnames to libfreeswan,
# which refers to the /usr/src/linux/net/ipsec/lib directory setup by the
# klink target in the top-level Makefile; and libdeslite.o to
# libdes/libdes.a.
# Added SUB_DIRS := lib definition for the kernel libraries.
#
# Revision 1.19  1999/04/27 19:06:47  rgb
# dd libs and dependancies to tags generation.
#
# Revision 1.18  1999/04/16 16:28:12  rgb
# Minor bugfix to avoid including DES if only AH is used.
#
# Revision 1.17  1999/04/15 15:37:23  rgb
# Forward check changes from POST1_00 branch.
#
# Revision 1.14.2.1  1999/03/30 17:29:17  rgb
# Add support for pfkey.
#
# Revision 1.16  1999/04/11 00:28:56  henry
# GPL boilerplate
#
# Revision 1.15  1999/04/06 04:54:25  rgb
# Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
# patch shell fixes.
#
# Revision 1.14  1999/02/18 16:50:45  henry
# update for new DES library
#
# Revision 1.13  1999/02/12 21:11:45  rgb
# Prepare for newer LIBDES (patch from P.Onion).
#
# Revision 1.12  1999/01/26 02:05:08  rgb
# Remove references to INET_GET_PROTOCOL.
# Removed CONFIG_IPSEC_ALGO_SWITCH macro.
# Change from transform switch to algorithm switch.
#
# Revision 1.11  1999/01/22 06:16:09  rgb
# Added algorithm switch code config option.
#
# Revision 1.10  1998/11/08 05:31:21  henry
# be a little fussier
#
# Revision 1.9  1998/11/08 05:29:41  henry
# revisions for new libdes handling
#
# Revision 1.8  1998/08/12 00:05:48  rgb
# Added new xforms to Makefile (moved des-cbc to des-old).
#
# Revision 1.7  1998/07/27 21:48:47  rgb
# Add libkernel.
#
# Revision 1.6  1998/07/14 15:50:47  rgb
# Add dependancies on linux config files.
#
# Revision 1.5  1998/07/09 17:44:06  rgb
# Added 'clean' and 'tags' targets.
# Added TOPDIR macro.
# Change module back from symbol exporting to not.
#
# Revision 1.3  1998/06/25 19:25:04  rgb
# Rearrange to support static linking and objects with exported symbol
# tables.
#
# Revision 1.1  1998/06/18 21:27:42  henry
# move sources from klips/src to klips/net/ipsec, to keep stupid
# kernel-build scripts happier in the presence of symlinks
#
# Revision 1.3  1998/04/15 23:18:43  rgb
# Unfixed the ../../libdes fix to avoid messing up Henry's script.
#
# Revision 1.2  1998/04/14 17:50:47  rgb
# Fixed to find the new location of libdes.
#
# Revision 1.1  1998/04/09 03:05:22  henry
# sources moved up from linux/net/ipsec
# modifications to centralize libdes code
#
# Revision 1.1.1.1  1998/04/08 05:35:02  henry
# RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
#
# Revision 0.5  1997/06/03 04:24:48  ji
# Added ESP-3DES-MD5-96
#
# Revision 0.4  1997/01/15 01:32:59  ji
# Added new transforms.
#
# Revision 0.3  1996/11/20 14:22:53  ji
# *** empty log message ***
#
#
# Local Variables:
# compile-command: "(cd ../../.. && source umlsetup.sh && make -C ${POOLSPACE} module/ipsec.o)"
# End Variables:
#

