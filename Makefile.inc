# FreeS/WAN pathnames and other master configuration
# Copyright (C) 2001, 2002  Henry Spencer.
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
# RCSID $Id: Makefile.inc,v 1.12 2006/01/25 17:23:15 as Exp $


# Variables in this file with names starting with INC_ are not for use
# by Makefiles which include it; they are subject to change without warning.
#
# "Final" and "finally" refer to where the files will end up on the
# running IPsec system, as opposed to where they get installed by our
# Makefiles.  (The two are different for cross-compiles and the like,
# where our Makefiles are not the end of the installation process.)
# Paths with FINAL in their names are the only ones that the installed
# software itself depends on.  (Very few things should know about the
# FINAL paths; think twice and consult Henry before making something new
# depend on them.)  All other paths are install targets.
# See also DESTDIR, below.


### boilerplate, do not change
SHELL=/bin/sh

### paths within the source tree

KLIPSINC=${FREESWANSRCDIR}/linux/include
KLIPSSRC=${FREESWANSRCDIR}/linux/net/ipsec

LIBFREESWANDIR=${FREESWANSRCDIR}/linux/lib/libfreeswan
FREESWANLIB=${FREESWANSRCDIR}/lib/libfreeswan/libfreeswan.a

LWRESDIR=${FREESWANSRCDIR}/lib/liblwres
LWRESLIB=${LWRESDIR}/liblwres.a

LIBDESSRCDIR=${FREESWANSRCDIR}/linux/crypto/ciphers/des
LIBDESLITE=${FREESWANSRCDIR}/lib/libdes/libdes.a

LIBPOLICYDIR=${FREESWANSRCDIR}/linux/lib/libipsecpolicy
POLICYLIB=${FREESWANSRCDIR}/lib/libipsecpolicy/libipsecpolicy.a

.PHONY:	programs checkprograms clean

### install pathnames

# DESTDIR can be used to supply a prefix to all install targets.
# (Note that "final" pathnames, signifying where files will eventually
# reside rather than where install puts them, are exempt from this.)
# The prefixing is done in this file, so as to have central control over
# it; DESTDIR itself should never appear in any other Makefile.
DESTDIR?=

# "local" part of tree, used in building other pathnames
INC_USRLOCAL=/usr/local

# PUBDIR is where the "ipsec" command goes; beware, many things define PATH
# settings which are assumed to include it (or at least, to include *some*
# copy of the "ipsec" command).
PUBDIR=$(DESTDIR)$(INC_USRLOCAL)/sbin

# BINDIR is where sub-commands get put, FINALBINDIR is where the "ipsec"
# command will look for them when it is run. Also called LIBEXECDIR.
FINALLIBEXECDIR=$(INC_USRLOCAL)/libexec/ipsec
LIBEXECDIR=$(DESTDIR)$(FINALBINDIR)

FINALBINDIR=${FINALLIBEXECDIR}
BINDIR=${LIBEXECDIR}


# SBINDIR is where the user interface command goes.
FINALSBINDIR=$(INC_USRLOCAL)/sbin
SBINDIR=$(DESTDIR)$(FINALSBINDIR)

# libdir is where utility files go
FINALLIBDIR=$(INC_USRLOCAL)/lib/ipsec
LIBDIR=$(DESTDIR)$(FINALLIBDIR)

# sharedlibdir is where shared libraries go
SHAREDLIBDIR=$(DESTDIR)$(INC_USRLOCAL)/lib

# where the appropriate manpage tree is located
# location within INC_USRLOCAL
INC_MANDIR=man
# the full pathname
MANTREE=$(DESTDIR)$(INC_USRLOCAL)/$(INC_MANDIR)
# all relevant subdirectories of MANTREE
MANPLACES=man3 man5 man8

# where configuration files go
FINALCONFFILE?=/etc/ipsec.conf
CONFFILE=$(DESTDIR)$(FINALCONFFILE)

FINALCONFDIR?=/etc
CONFDIR=$(DESTDIR)$(FINALCONFDIR)

FINALCONFDDIR?=${FINALCONFDIR}/ipsec.d
CONFDDIR=$(DESTDIR)$(FINALCONFDDIR)

# sample configuration files go into
INC_DOCDIR?=share/doc
FINALEXAMPLECONFDIR=${INC_USRLOCAL}/${INC_DOCDIR}/strongswan
EXAMPLECONFDIR=${DESTDIR}${FINALEXAMPLECONFDIR}

FINALDOCDIR?=${INC_USRLOCAL}/${INC_DOCDIR}/strongswan
DOCDIR=${DESTDIR}${FINALDOCDIR}

# where per-conn pluto logs go
VARDIR?=/var
LOGDIR?=${VARDIR}/log
FINALLOGDIR?=${DESTDIR}${LOGDIR}


# An attempt is made to automatically figure out where boot/shutdown scripts 
# will finally go:  the first directory in INC_RCDIRS which exists gets them.
# If none of those exists (or INC_RCDIRS is empty), INC_RCDEFAULT gets them.
# With a non-null DESTDIR, INC_RCDEFAULT will be used unless one of the
# INC_RCDIRS directories has been pre-created under DESTDIR.
INC_RCDIRS=/etc/rc.d/init.d /etc/rc.d /etc/init.d /sbin/init.d
INC_RCDEFAULT=/etc/rc.d/init.d

# RCDIR is where boot/shutdown scripts go; FINALRCDIR is where they think
# will finally be (so utils/Makefile can create a symlink in BINDIR to the
# place where the boot/shutdown script will finally be, rather than the
# place where it is installed).
FINALRCDIR=$(shell for d in $(INC_RCDIRS) ; \
		do if test -d $(DESTDIR)/$$d ; \
		then echo $$d ; exit 0 ; \
		fi ; done ; echo $(INC_RCDEFAULT) )
RCDIR=$(DESTDIR)$(FINALRCDIR)



### kernel pathnames

# Kernel location:  where patches are inserted, where kernel builds are done.

# this is a hack using the wildcard to look for existence of a file/dir
ifneq ($(wildcard /usr/src/linux-2.4),)
KERNELSRC?=/usr/src/linux-2.4
else
KERNELSRC?=/usr/src/linux
endif


# where kernel configuration outputs are located
KCFILE=$(KERNELSRC)/.config
ACFILE=$(KERNELSRC)/include/linux/autoconf.h
VERFILE=$(KERNELSRC)/include/linux/version.h



### misc installation stuff

# what program to use when installing things
INSTALL=install

# flags to the install program, for programs, manpages, and config files
# -b has install make backups (n.b., unlinks original), --suffix controls
# how backup names are composed.
# Note that the install procedures will never overwrite an existing config
# file, which is why -b is not specified for them.
INSTBINFLAGS=-b --suffix=.old
INSTMANFLAGS=
INSTCONFFLAGS=


### misc configuration, included here in hopes that other files will not
### have to be changed for common customizations.

# extra compile flags, for userland and kernel stuff, e.g. -g for debug info
# (caution, this stuff is still being sorted out, will change in future)
USERCOMPILE?=-g -O3
KLIPSCOMPILE=-O3

# command used to link/copy KLIPS into kernel source tree
# There are good reasons why this is "ln -s"; only people like distribution
# builders should ever change it.
KLIPSLINK=ln -s -f

# extra options for use in kernel build
KERNMAKEOPTS=

# kernel Makefile targets to be done before build
# Can be overridden if you are *sure* your kernel doesn't need them.  (2.2.xx
# and later reportedly do not.)
KERNDEP=dep
KERNCLEAN=clean

# kernel make name:  zImage for 2.0.xx, bzImage for 2.2.xx and later, and
# boot on non-x86s (what ever happened to standards?)
INC_B=$(shell test -d $(DIRIN22) && echo b)
KERNEL=$(shell if expr " `uname -m`" : ' i.86' >/dev/null ; \
	then echo $(INC_B)zImage ; \
	else echo boot ; \
	fi)

# temporary directory to be used when building RPMs, and where to put the
# resulting RPM tree
RPMKERNDIR := $(shell echo `pwd`/tmp.rpmkernel)
RPMTMPDIR := $(shell echo `pwd`/tmp.rpmbuild)
RPMDEST := $(shell echo `pwd`/rpms)

# Newer versions of RPM do not permit building of packages with the "rpm" 
# command. For RedHat systems with older version of RPM, use:
# RPMBUILD=rpm
# instead.
RPMBUILD=rpmbuild

### paths to resources on the host system
#
# Set this to a RedHat kernel-sources RPM. This normally extracts into
# /usr/src/linux-2.4, but you might have extracted it elsewhere with
# rpm2cpio.
#
RH_KERNELSRC?=/usr/src/linux-2.4

## build environment variations
##

# set this to a place where you have installed a bind9.3 
# snapshot (20021115 or better). A bind 9.2, particularly a RedHat
# installed one in RH 7.2, won't work - you wind up depending upon
# openssl.

BIND9STATICLIBDIR?=/usr/local/lib

# FreeSWAN 3.x will require bind9. 
USE_LWRES?=false

# whether or not to use iproute2 based commands.
#
USE_IPROUTE2?=true

# what kind of firewalling to use:
#  2.0 	- ipfwadm
#  2.2  - ipchains
#  2.4  - iptables
IPSEC_FIREWALLTYPE=iptables

# whether or not to include ipsec policy code into pluto.
# false for now, since it is still experimental.
USE_IPSECPOLICY?=false

# include IKEPING in the distribution
USE_IKEPING?=false

# include support for KEY RR 
# this will become false in late 2003.
USE_KEYRR?=true

# include support for KERNEL 2.5/2.6 IPsec in pluto
USE_KERNEL26?=true

# whether or not pluto sends its strongSwan Vendor ID
USE_VENDORID?=true

# whether or not pluto sends an XAUTH VID (Cisco Mode Config Interoperability)
USE_XAUTH_VID?=false

# whether to support NAT Traversal (aka NAT-T)
USE_NAT_TRAVERSAL?=true

# whether to support NAT-T in transport mode (needed for Win2K NAT-T Interop)
USE_NAT_TRAVERSAL_TRANSPORT_MODE?=false

# include libcurl support (currently used for fetching CRLs, OCSP and SCEP)
USE_LIBCURL?=false

# include LDAP support (currently used for fetching CRLs)
USE_LDAP?=false

# uncomment this line if using the LDAPv3 protocol
LDAP_VERSION=3
# uncomment this line if using the LDAPv2 protocol
#LDAP_VERSION=2

# include PKCS11-based smartcard support
USE_SMARTCARD?=false

# support IKEv2 via charon
USE_IKEV2?=true

# Default PKCS11 library
# Uncomment this line if using OpenSC <= 0.9.6
PKCS11_DEFAULT_LIB=\"/usr/lib/pkcs11/opensc-pkcs11.so\"
# Uncomment this line if using OpenSC >= 0.10.0
#PKCS11_DEFAULT_LIB=\"/usr/lib/opensc-pkcs11.so\"
# Uncomment and complete this line if using another default library
#PKCS11_DEFAULT_LIB=\"/usr/lib/...\"

# Enable the leak detective to find memory leaks
USE_LEAK_DETECTIVE?=false

# set this to space where a linked/configured tree can be created by
# preprhkern4module. Only needed if you are going to be created RPMs
# outside of a distribution (as the FS team does for RedHat).
#RH_KERNELSRC_POOL=/c2/freeswan/rh_kern

# the following is a list of symbols which will be used to construct
# the module goo to identify which module goes with each kernel.
MODULE_GOO_LIST=irq_stat netif_rx register_sysctl_table send_sig
MODULE_GOO_LIST+=kmalloc __kfree_skb __ip_select_ident alloc_skb
MODULE_GOO_LIST+=icmp_send ip_fragment sock_register 

MODULE_DEF_INCLUDE=${FREESWANSRCDIR}/packaging/linus/config-all.h
MODULE_DEFCONFIG?=${KLIPSSRC}/defconfig

MODULE_FLAGS:=KLIPSMODULE=true TOPDIR=${KERNELSRC} -f ${MODULE_DEFCONFIG} -f Makefile

# supply kernel-configuration ARCH defaults
ifeq ($(ARCH),)
ARCH := $(shell uname -m)
endif
# always sanitize $(ARCH)
ARCH := $(shell echo $(ARCH) | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)

# export everything so that scripts can use them.
export LIBFREESWANDIR FREESWANSRCDIR FREESWANLIB

-include ${FREESWANSRCDIR}/Makefile.ver

# for emacs
#
# Local Variables: ;;;
# mode: makefile ;;;
# End Variables: ;;;
#
