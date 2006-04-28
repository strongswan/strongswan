# Pluto Makefile
# Copyright (C) 1997 Angelos D. Keromytis.
# Copyright (C) 1998-2001  D. Hugh Redelmeier
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
# RCSID $Id: Makefile,v 1.44 2006/01/25 17:22:19 as Exp $

# relative path to top directory of FreeS/WAN source
# Note: referenced in ${FREESWANSRCDIR}/Makefile.inc
FREESWANSRCDIR=../..

include ${FREESWANSRCDIR}/Makefile.inc

FMANDIR=$(MANTREE)/man5
PMANDIR=$(MANTREE)/man8

# -O on Linux makes gcc coredump when compiling sha1.c
# -Wundef is nice but RHL5.2 compiler doesn't support it
CFLAGS = -g -Wall -W -Wmissing-prototypes -Wpointer-arith -Wbad-function-cast \
	-Wcast-qual -Wmissing-declarations -Wwrite-strings \
	-Wstrict-prototypes # -Wundef

# where to find klips headers and FreeS/WAN headers
HDRDIRS = -I$(KLIPSINC) -I${FREESWANSRCDIR}/programs/pluto/linux26

# where to find sha2.h
LIBCRYPTO=$(FREESWANSRCDIR)/lib/libcrypto
HDRDIRS += -I$(LIBCRYPTO)

# On non-LINUX systems, these one of these may be needed (see endian.h)
# BYTE_ORDER = -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=BIG_ENDIAN
# BYTE_ORDER = -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN

# -DKLIPS enables interface to Kernel LINUX IPsec code
# -DDEBUG enables debugging code, allowing for debugging output
#    (note that output must also be selected at runtime, so it is
#    reasonable to always define this)
# -DVENDORID enables Pluto to send out a VendorID payload.
#    this can be used by remote nodes to work around faults (bugs),
#    but is most useful to humans who are debugging things.
# -DGCC_LINT uses gcc-specific declarations to improve compile-time
#    diagnostics.
# -DLEAK_DETECTIVE enables crude code to find memory allocation leaks.
# -DOLD_RESOLVER.  At some point, the resolver interface changed.
#    This macro enables Pluto support for the old interface.
#    It is automatically defined, based on the value of the <resolver.h>
#    macro __RES.  We don't know the correct threshold, so you may
#    find that you must manually define this.  If so, please inform
#    us so that we can refine the threshold.
# -DLIBCURL includes libcurl functions for the support of http-based protocols.
# -DLDAP_VER includes openldap functions for the support of ldap-based queries.
#    LDAPv2 and LDAPv3 are supported.
# -DTHREADS enables an asynchronous thread managing CRL fetching.
#    This option is activated either by -DLIBCURL or -DLDAP_VER.
# -DSMARTCARD enables PKCS11-based smartcard support
# -DPKCS11_DEFAULT_LIB defines a default PKCS11 library module which will be
#    loaded during runtime and is overridden by the pkcs11module parameter in
#    ipsec.conf. This option is activated by -DSMARTCARD.
# -DI_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
#     allows IPsec transport mode in NAT-ed environments. Because of the 
#     inherent security risks of such scenarios this options is deactivated
#     by default.

# The following are best left undefined -- each can be overridden at runtime
# if need be.
# -DPORT=n sets the default UDP port for IKE messages (otherwise 500)
# -DSHARED_SECRETS_FILE=string overrides /etc/ipsec.secrets as the
#    default name of the file containing secrets used to authenticate other
#    IKE daemons.  In the Makefile, two levels of quoting are needed:
# -DSHARED_SECRETS_FILE='"/etc/ipsec.secrets"'
# -DDEFAULT_CTLBASE=string overrides /var/run/pluto as default directory
#    and basename for pluto's lockfile (.pid) and control socket (.ctl).
#    Double quoting may be needed.

ifeq ($(USE_LWRES),true)
  LWRESDEF=-DUSE_LWRES
  USE_ADNS=false
  BINNAMEADNSIFNEEDE=
else
  USE_ADNS=true
  BINNAMEADNSIFNEEDED=$(BINNAMEADNS)
endif

ifeq ($(USE_IPSECPOLICY),true)
  IPSECPOLICY_FILES=rcv_info.c
  IPSECPOLICY_DEFINES=-DIPSECPOLICY
  IPSECPOLICY_LIBS=$(POLICYLIB)
  IPSECPOLICY_OBJS=rcv_info.o
endif

ifeq ($(USE_KEYRR),true)
  KEYRR_DEFINES=-DUSE_KEYRR
endif

ifeq ($(USE_KERNEL26),true)
  KERNEL26_DEFS=-DKERNEL26_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES
  KERNEL26_SRCS=kernel_netlink.c kernel_netlink.h
  KERNEL26_OBJS=kernel_netlink.o
endif

ifeq ($(USE_NAT_TRAVERSAL),true)
NAT_DEFS=-DNAT_TRAVERSAL -DVIRTUAL_IP
endif

ifeq ($(USE_NAT_TRAVERSAL_TRANSPORT_MODE),true)
NAT_DEFS+=-DI_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
endif

DEFINES = $(EXTRA_DEFINES) \
	$(IPSECPOLICY_DEFINES) \
	$(KEYRR_DEFINES) \
	$(BYTE_ORDER) \
	$(LWRESDEF) \
	$(KERNEL26_DEFS) \
	-DPLUTO \
	-DKLIPS \
	-DDEBUG \
	-DGCC_LINT \
	$(NAT_DEFS)

# libefence is a free memory allocation debugger
# Solaris 2 needs -lsocket -lnsl
LIBSPLUTO = $(OBJSGCRYPT) $(LIBDESLITE) $(FREESWANLIB) $(IPSECPOLICY_LIBS)
LIBSPLUTO+= -lgmp -lresolv # -lefence


ifeq ($(USE_VENDORID),true)
  DEFINES+= -DVENDORID
endif

ifeq ($(USE_XAUTH_VID),true)
  DEFINES+= -DXAUTH_VID
endif

# This compile option activates dynamic URL fetching using libcurl
ifeq ($(USE_LIBCURL),true)
  DEFINES+= -DLIBCURL
  LIBSPLUTO+= -lcurl
  THREADS=1   # Asynchronous cURL queries require threads
endif

# This compile option activates dynamic LDAP CRL fetching
ifeq ($(USE_LDAP),true)
  DEFINES+= -DLDAP_VER=$(LDAP_VERSION)
  LIBSPLUTO+= -lldap -llber
  THREADS=1   # Asynchronous LDAP queries require threads
endif

# This compile option activates the use of threads
ifdef THREADS
  DEFINES+= -DTHREADS
  LIBSPLUTO+= -lpthread
endif

# This compile option activates smartcard support
ifeq ($(USE_SMARTCARD),true)
  DEFINES+= -DSMARTCARD
  ifdef PKCS11_DEFAULT_LIB
    DEFINES+= -DPKCS11_DEFAULT_LIB=$(PKCS11_DEFAULT_LIB)
  endif
  LIBSPLUTO+= -ldl
endif

# enable IKEv2 support
ifeq ($(USE_IKEV2),true)
  DEFINES+= -DIKEV2
endif

# This compile option activates the leak detective
ifeq ($(USE_LEAK_DETECTIVE),true)
  DEFINES+= -DLEAK_DETECTIVE
endif

CPPFLAGS = $(HDRDIRS) $(DEFINES) \
	-DSHARED_SECRETS_FILE=\"${FINALCONFDIR}/ipsec.secrets\" \
	-DPOLICYGROUPSDIR=\"${FINALCONFDDIR}/policies\" \
	-DPERPEERLOGDIR=\"${FINALLOGDIR}/pluto/peer\"

ALLFLAGS = $(CPPFLAGS) $(CFLAGS) $(USERCOMPILE)

ifneq ($(LD_LIBRARY_PATH),)
  LDFLAGS=-L$(LD_LIBRARY_PATH)
endif

LIBSADNS = $(FREESWANLIB)
LIBSADNS += -lresolv # -lefence

# Solaris needs -lsocket -lnsl
LIBSWHACK = ${FREESWANLIB}

BINNAMEPLUTO = pluto
BINNAMEWHACK = whack
BINNAMEADNS = _pluto_adns

RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

# files for a (source) distribution

DISTMISC = CHANGES PLUTO-CONVENTIONS TODO ipsec.secrets Makefile routing.txt \
	 pluto.8 ipsec.secrets.5 .cvsignore

DISTGCRYPT = \
	gcryptfix.c gcryptfix.h \
	dsa.c dsa.h \
	elgamal.c elgamal.h \
	primegen.c \
	smallprime.c

DISTSRC = \
	ac.c ac.h \
	asn1.c asn1.h \
	ca.c ca.h \
	certs.c certs.h \
	connections.c connections.h \
	crl.c crl.h \
	foodgroups.c foodgroups.h \
	constants.c constants.h \
	cookie.c cookie.h \
	crypto.h crypto.c \
	defs.h defs.c \
	mp_defs.h mp_defs.c \
	demux.c demux.h \
	dnskey.c dnskey.h \
	fetch.c fetch.h \
	id.c id.h \
	ipsec_doi.c ipsec_doi.h \
	kernel.c kernel.h \
	kernel_netlink.c kernel_netlink.h \
	kernel_pfkey.c kernel_pfkey.h \
	kernel_noklips.c kernel_noklips.h \
	kernel_alg.c kernel_alg.h \
	ike_alg.c ike_alg.h \
	alg_info.c alg_info.h \
	rcv_whack.c rcv_whack.h \
	$(IPSECPOLICY_FILES) \
	log.c log.h \
	plutomain.c \
	md2.c md2.h \
	md5.c md5.h \
	modecfg.c modecfg.h \
	ocsp.c ocsp.h \
	oid.txt oid.pl oid.c oid.h \
	packet.c packet.h \
	pem.c pem.h \
	pgp.c pgp.h \
	pkcs1.c pkcs1.h \
	pkcs7.c pkcs7.h \
	lex.c lex.h \
	keys.c keys.h \
	rnd.c rnd.h \
	server.c server.h \
	sha1.c sha1.h \
	smartcard.c smartcard.h \
	spdb.c spdb.h \
	state.c state.h \
	timer.c timer.h \
	x509.c x509.h \
	$(DISTGCRYPT) \
	vendor.c nat_traversal.c virtual.c \
	adns.c adns.h \
	whack.c whack.h

DIST = $(DISTMISC) $(DISTSRC)


# start of support for DSS/DSA.  Not currently used.
# OBJSGCRYPT =  gcryptfix.o dsa.o elgamal.o primegen.o smallprime.o
OBJSGCRYPT =

OBJSPLUTO = asn1.o connections.o constants.o cookie.o crypto.o defs.o fetch.o foodgroups.o \
	log.o state.o plutomain.o server.o timer.o oid.o pem.o pgp.o pkcs1.o pkcs7.o x509.o \
	ca.o certs.o id.o ipsec_doi.o kernel.o $(KERNEL26_OBJS) kernel_pfkey.o mp_defs.o \
	kernel_noklips.o rcv_whack.o ${IPSECPOLICY_OBJS} demux.o packet.o lex.o keys.o \
	dnskey.o smartcard.o ac.o rnd.o spdb.o sha1.o md5.o md2.o modecfg.o ocsp.o crl.o \
	vendor.o nat_traversal.o virtual.o

OBJSADNS = adns.o

OBJSWHACK = whack.o

all: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK)
programs: $(BINNAMEPLUTO) $(BINNAMEADNSIFNEEDED) $(BINNAMEWHACK)

oid.c: oid.txt oid.pl
	perl oid.pl

oid.h: oid.txt oid.pl
	perl oid.pl

install: all
	mkdir -p ${LIBEXECDIR} ${LIBDIR}
	mkdir -p -m 755 $(CONFDIR)/ipsec.d
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/cacerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/ocspcerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/certs
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/acerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/aacerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/crls
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/reqs
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/private
	$(INSTALL) $(INSTBINFLAGS) $(BINNAMEPLUTO) $(BINNAMEWHACK) $(LIBEXECDIR)
	if $(USE_ADNS) ; then $(INSTALL) $(INSTBINFLAGS) $(BINNAMEADNS)                  $(LIBDIR) ; fi
	$(INSTALL) $(INSTMANFLAGS) pluto.8 $(PMANDIR)/ipsec_pluto.8
	sh ${FREESWANSRCDIR}/utils/manlink pluto.8 | \
		while read from to ; \
		do \
			ln -s -f ipsec_$$from $(PMANDIR)/$$to; \
		done
	$(INSTALL) $(INSTMANFLAGS) ipsec.secrets.5 $(FMANDIR)
	sh ${FREESWANSRCDIR}/utils/manlink ipsec.secrets.5 | \
		while read from to ; \
		do \
		 ln -s -f $$from $(FMANDIR)/$$to; \
		done

install_file_list:
	@echo $(LIBEXECDIR)/$(BINNAMEPLUTO)
	@if $(USE_ADNS) ; then echo $(LIBDIR)/$(BINNAMEADNS) ; fi
	@echo $(LIBEXECDIR)/$(BINNAMEWHACK)
	@echo $(PMANDIR)/ipsec_pluto.8
	@sh ${FREESWANSRCDIR}/utils/manlink pluto.8 | \
		while read from to; \
		do\
			 echo $(PMANDIR)/$$to; \
		done
	@echo $(FMANDIR)/ipsec.secrets.5
	@sh ${FREESWANSRCDIR}/utils/manlink ipsec.secrets.5 | \
		while read from to; \
		do \
			echo $(FMANDIR)/$$to; \
		done

alg_info_test: alg_info_test.o alg_info.o kernel_alg.o ike_alg.o constants.o defs.o log.o db_ops.o crypto.o $(LIBDESLITE) $(FREESWANLIB)
	$(CC) -o $@ $^ $(LIBSPLUTO)

# alg/libalg.o contains an already resolved object built with
# additional crypto algos inside.
OBJSPLUTO:= kernel_alg.o ike_alg.o alg_info.o db_ops.o $(OBJSPLUTO) alg/libalg.o 
# if new alg source is created in alg directory,
# trigger libalg.o rebuild
alg/libalg.o: alg alg/Config.ike_alg
	make -C alg libalg.o
	touch alg/libalg.o

# helper for creating alg/Make.common
showdefs:
	@echo DEFINES=$(DEFINES)
	@echo CFLAGS=$(CFLAGS)
	@echo CPPFLAGS=$(CPPFLAGS)
	@echo COPTS=$(COPTS)

$(BINNAMEPLUTO): $(OBJSPLUTO) $(ALG_LIBS)
	$(CC) -o $(BINNAMEPLUTO) $(LDFLAGS) $(OBJSPLUTO) $(LIBSPLUTO)

$(BINNAMEADNS): $(OBJSADNS)
	$(CC) -o $(BINNAMEADNS) $(OBJSADNS) $(LIBSADNS)

$(BINNAMEWHACK): $(OBJSWHACK)
	$(CC) -o $(BINNAMEWHACK) $(OBJSWHACK) $(LIBSWHACK)

distlist:
	@echo $(DIST)

# Exuberant Ctags doesn't work if LC_ALL is set to something other than C

CTAGSFLAGS = -N --format=1 # fishy options required for Exuberant Ctags

tags:	$(DISTSRC)
	LC_ALL=C ctags $(CTAGSFLAGS) $(DISTSRC) $(LIBFREESWANDIR)/*.[ch]

TAGS:	$(DISTSRC)
	LC_ALL=C etags $(ETAGSFLAGS) $(DISTSRC) $(LIBFREESWANDIR)/*.[ch]

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

clean:
	$(RM) $(RMFLAGS) *.core core *~ a.out ktrace.out \
		$(OBJSPLUTO) $(BINNAMEPLUTO) \
		$(OBJSWHACK) $(BINNAMEWHACK) \
		$(OBJSADNS) $(BINNAMEADNS)
	make -C alg clean

check:
	echo no checks in lib right now.

checkprograms:

.c.o:
	$(CC) $(COPTS) $(ALLFLAGS) -c $<

# Gather dependencies caused by explicit #includes within .c files
#
# Each .c is assumed to compile into a .o with the corresponding name.
# Only dependencies on based on "" includes are considered, not <>.
# Dependencies caused by includes within headers are not noticed.
# Unlike dependencies generated by the compiler, these include dependencies
# suppressed by conditional compilation (good, we think).
# This code can be tricked by embeding #include in comments or
# vice-versa, but we're among friends.

gatherdeps:
	@ls $(DISTSRC) | grep '\.c' | sed -e 's/\(.*\)\.c$$/\1.o: \1.c/'
	@echo
	@ls $(DISTSRC) | grep '\.c' | xargs grep '^#[ 	]*include[ 	]*"' | \
		sed -e 's/\.c:#[ 	]*include[ 	]*"/.o: /' -e 's/".*//'

# Dependencies generated by "make gatherdeps":

ac.o: ac.c
adns.o: adns.c
alg_info.o: alg_info.c
asn1.o: asn1.c
ca.o: ca.c
certs.o: certs.c
connections.o: connections.c
constants.o: constants.c
cookie.o: cookie.c
crl.o: crl.c
crypto.o: crypto.c
defs.o: defs.c
demux.o: demux.c
dnskey.o: dnskey.c
dsa.o: dsa.c
elgamal.o: elgamal.c
fetch.o: fetch.c
foodgroups.o: foodgroups.c
gcryptfix.o: gcryptfix.c
id.o: id.c
ike_alg.o: ike_alg.c
ipsec_doi.o: ipsec_doi.c
kernel.o: kernel.c
kernel_alg.o: kernel_alg.c
kernel_netlink.o: kernel_netlink.c
kernel_noklips.o: kernel_noklips.c
kernel_pfkey.o: kernel_pfkey.c
keys.o: keys.c
lex.o: lex.c
log.o: log.c
md2.o: md2.c
md5.o: md5.c
modecfg.o: modecfg.c
mp_defs.o: mp_defs.c
nat_traversal.o: nat_traversal.c
ocsp.o: ocsp.c
oid.o: oid.c
packet.o: packet.c
pem.o: pem.c
pgp.o: pgp.c
pkcs1.o: pkcs1.c
pkcs7.o: pkcs7.c
plutomain.o: plutomain.c
primegen.o: primegen.c
rcv_whack.o: rcv_whack.c
rnd.o: rnd.c
server.o: server.c
sha1.o: sha1.c
smallprime.o: smallprime.c
smartcard.o: smartcard.c
spdb.o: spdb.c
state.o: state.c
timer.o: timer.c
vendor.o: vendor.c
virtual.o: virtual.c
whack.o: whack.c
x509.o: x509.c

ac.o: constants.h
ac.o: defs.h
ac.o: asn1.h
ac.o: oid.h
ac.o: ac.h
ac.o: x509.h
ac.o: crl.h
ac.o: ca.h
ac.o: certs.h
ac.o: log.h
ac.o: whack.h
ac.o: fetch.h
adns.o: constants.h
adns.o: adns.h
alg_info.o: alg_info.h
alg_info.o: constants.h
alg_info.o: defs.h
alg_info.o: log.h
alg_info.o: whack.h
alg_info.o: sha1.h
alg_info.o: md5.h
alg_info.o: crypto.h
alg_info.o: kernel_alg.h
alg_info.o: ike_alg.h
asn1.o: constants.h
asn1.o: defs.h
asn1.o: mp_defs.h
asn1.o: asn1.h
asn1.o: oid.h
asn1.o: log.h
ca.o: constants.h
ca.o: defs.h
ca.o: log.h
ca.o: x509.h
ca.o: ca.h
ca.o: certs.h
ca.o: whack.h
ca.o: fetch.h
certs.o: constants.h
certs.o: defs.h
certs.o: log.h
certs.o: asn1.h
certs.o: id.h
certs.o: x509.h
certs.o: pgp.h
certs.o: pem.h
certs.o: certs.h
certs.o: pkcs1.h
connections.o: kameipsec.h
connections.o: constants.h
connections.o: defs.h
connections.o: id.h
connections.o: x509.h
connections.o: ca.h
connections.o: crl.h
connections.o: pgp.h
connections.o: certs.h
connections.o: ac.h
connections.o: smartcard.h
connections.o: fetch.h
connections.o: connections.h
connections.o: foodgroups.h
connections.o: demux.h
connections.o: state.h
connections.o: timer.h
connections.o: ipsec_doi.h
connections.o: server.h
connections.o: kernel.h
connections.o: log.h
connections.o: keys.h
connections.o: adns.h
connections.o: dnskey.h
connections.o: whack.h
connections.o: alg_info.h
connections.o: ike_alg.h
connections.o: kernel_alg.h
connections.o: nat_traversal.h
connections.o: virtual.h
constants.o: constants.h
constants.o: defs.h
constants.o: log.h
constants.o: packet.h
cookie.o: constants.h
cookie.o: defs.h
cookie.o: sha1.h
cookie.o: rnd.h
cookie.o: cookie.h
crl.o: constants.h
crl.o: defs.h
crl.o: log.h
crl.o: asn1.h
crl.o: oid.h
crl.o: x509.h
crl.o: crl.h
crl.o: ca.h
crl.o: certs.h
crl.o: keys.h
crl.o: whack.h
crl.o: fetch.h
crl.o: sha1.h
crypto.o: constants.h
crypto.o: defs.h
crypto.o: state.h
crypto.o: log.h
crypto.o: md5.h
crypto.o: sha1.h
crypto.o: crypto.h
crypto.o: alg_info.h
crypto.o: ike_alg.h
defs.o: constants.h
defs.o: defs.h
defs.o: log.h
defs.o: whack.h
demux.o: constants.h
demux.o: defs.h
demux.o: cookie.h
demux.o: connections.h
demux.o: state.h
demux.o: packet.h
demux.o: md5.h
demux.o: sha1.h
demux.o: crypto.h
demux.o: ike_alg.h
demux.o: log.h
demux.o: demux.h
demux.o: ipsec_doi.h
demux.o: timer.h
demux.o: whack.h
demux.o: server.h
demux.o: nat_traversal.h
demux.o: vendor.h
demux.o: modecfg.h
dnskey.o: constants.h
dnskey.o: adns.h
dnskey.o: defs.h
dnskey.o: log.h
dnskey.o: id.h
dnskey.o: connections.h
dnskey.o: keys.h
dnskey.o: dnskey.h
dnskey.o: packet.h
dnskey.o: timer.h
dsa.o: constants.h
dsa.o: defs.h
dsa.o: log.h
dsa.o: rnd.h
dsa.o: gcryptfix.h
dsa.o: dsa.h
elgamal.o: constants.h
elgamal.o: defs.h
elgamal.o: log.h
elgamal.o: rnd.h
elgamal.o: gcryptfix.h
elgamal.o: elgamal.h
fetch.o: constants.h
fetch.o: defs.h
fetch.o: log.h
fetch.o: id.h
fetch.o: asn1.h
fetch.o: pem.h
fetch.o: x509.h
fetch.o: ca.h
fetch.o: whack.h
fetch.o: ocsp.h
fetch.o: crl.h
fetch.o: fetch.h
foodgroups.o: constants.h
foodgroups.o: defs.h
foodgroups.o: connections.h
foodgroups.o: foodgroups.h
foodgroups.o: kernel.h
foodgroups.o: lex.h
foodgroups.o: log.h
foodgroups.o: whack.h
gcryptfix.o: constants.h
gcryptfix.o: defs.h
gcryptfix.o: log.h
gcryptfix.o: rnd.h
gcryptfix.o: gcryptfix.h
id.o: constants.h
id.o: defs.h
id.o: id.h
id.o: log.h
id.o: connections.h
id.o: packet.h
id.o: whack.h
ike_alg.o: constants.h
ike_alg.o: defs.h
ike_alg.o: sha1.h
ike_alg.o: md5.h
ike_alg.o: crypto.h
ike_alg.o: state.h
ike_alg.o: packet.h
ike_alg.o: log.h
ike_alg.o: whack.h
ike_alg.o: spdb.h
ike_alg.o: alg_info.h
ike_alg.o: ike_alg.h
ike_alg.o: db_ops.h
ike_alg.o: connections.h
ike_alg.o: kernel.h
ipsec_doi.o: constants.h
ipsec_doi.o: defs.h
ipsec_doi.o: mp_defs.h
ipsec_doi.o: state.h
ipsec_doi.o: id.h
ipsec_doi.o: x509.h
ipsec_doi.o: crl.h
ipsec_doi.o: ca.h
ipsec_doi.o: certs.h
ipsec_doi.o: smartcard.h
ipsec_doi.o: connections.h
ipsec_doi.o: keys.h
ipsec_doi.o: packet.h
ipsec_doi.o: demux.h
ipsec_doi.o: adns.h
ipsec_doi.o: dnskey.h
ipsec_doi.o: kernel.h
ipsec_doi.o: log.h
ipsec_doi.o: cookie.h
ipsec_doi.o: server.h
ipsec_doi.o: spdb.h
ipsec_doi.o: timer.h
ipsec_doi.o: rnd.h
ipsec_doi.o: ipsec_doi.h
ipsec_doi.o: whack.h
ipsec_doi.o: fetch.h
ipsec_doi.o: pkcs7.h
ipsec_doi.o: asn1.h
ipsec_doi.o: sha1.h
ipsec_doi.o: md5.h
ipsec_doi.o: crypto.h
ipsec_doi.o: vendor.h
ipsec_doi.o: alg_info.h
ipsec_doi.o: ike_alg.h
ipsec_doi.o: kernel_alg.h
ipsec_doi.o: nat_traversal.h
ipsec_doi.o: virtual.h
kernel.o: kameipsec.h
kernel.o: constants.h
kernel.o: defs.h
kernel.o: rnd.h
kernel.o: id.h
kernel.o: connections.h
kernel.o: state.h
kernel.o: timer.h
kernel.o: kernel.h
kernel.o: kernel_netlink.h
kernel.o: kernel_pfkey.h
kernel.o: kernel_noklips.h
kernel.o: log.h
kernel.o: ca.h
kernel.o: server.h
kernel.o: whack.h
kernel.o: keys.h
kernel.o: packet.h
kernel.o: nat_traversal.h
kernel.o: alg_info.h
kernel.o: kernel_alg.h
kernel_alg.o: constants.h
kernel_alg.o: defs.h
kernel_alg.o: connections.h
kernel_alg.o: state.h
kernel_alg.o: packet.h
kernel_alg.o: spdb.h
kernel_alg.o: kernel.h
kernel_alg.o: kernel_alg.h
kernel_alg.o: alg_info.h
kernel_alg.o: log.h
kernel_alg.o: whack.h
kernel_alg.o: db_ops.h
kernel_netlink.o: kameipsec.h
kernel_netlink.o: linux26/rtnetlink.h
kernel_netlink.o: linux26/xfrm.h
kernel_netlink.o: constants.h
kernel_netlink.o: defs.h
kernel_netlink.o: kernel.h
kernel_netlink.o: kernel_netlink.h
kernel_netlink.o: kernel_pfkey.h
kernel_netlink.o: log.h
kernel_netlink.o: whack.h
kernel_netlink.o: kernel_alg.h
kernel_noklips.o: constants.h
kernel_noklips.o: defs.h
kernel_noklips.o: kernel.h
kernel_noklips.o: kernel_noklips.h
kernel_noklips.o: log.h
kernel_noklips.o: whack.h
kernel_pfkey.o: constants.h
kernel_pfkey.o: defs.h
kernel_pfkey.o: kernel.h
kernel_pfkey.o: kernel_pfkey.h
kernel_pfkey.o: log.h
kernel_pfkey.o: whack.h
kernel_pfkey.o: demux.h
kernel_pfkey.o: nat_traversal.h
kernel_pfkey.o: alg_info.h
kernel_pfkey.o: kernel_alg.h
keys.o: constants.h
keys.o: defs.h
keys.o: mp_defs.h
keys.o: id.h
keys.o: x509.h
keys.o: pgp.h
keys.o: certs.h
keys.o: smartcard.h
keys.o: connections.h
keys.o: state.h
keys.o: lex.h
keys.o: keys.h
keys.o: adns.h
keys.o: dnskey.h
keys.o: log.h
keys.o: whack.h
keys.o: timer.h
keys.o: fetch.h
keys.o: nat_traversal.h
lex.o: constants.h
lex.o: defs.h
lex.o: log.h
lex.o: whack.h
lex.o: lex.h
log.o: constants.h
log.o: defs.h
log.o: log.h
log.o: server.h
log.o: state.h
log.o: connections.h
log.o: kernel.h
log.o: whack.h
log.o: timer.h
md2.o: md2.h
md5.o: md5.h
modecfg.o: constants.h
modecfg.o: defs.h
modecfg.o: state.h
modecfg.o: demux.h
modecfg.o: timer.h
modecfg.o: ipsec_doi.h
modecfg.o: log.h
modecfg.o: md5.h
modecfg.o: sha1.h
modecfg.o: crypto.h
modecfg.o: modecfg.h
modecfg.o: whack.h
mp_defs.o: constants.h
mp_defs.o: defs.h
mp_defs.o: mp_defs.h
mp_defs.o: log.h
nat_traversal.o: constants.h
nat_traversal.o: defs.h
nat_traversal.o: log.h
nat_traversal.o: server.h
nat_traversal.o: state.h
nat_traversal.o: connections.h
nat_traversal.o: packet.h
nat_traversal.o: demux.h
nat_traversal.o: kernel.h
nat_traversal.o: whack.h
nat_traversal.o: timer.h
nat_traversal.o: cookie.h
nat_traversal.o: sha1.h
nat_traversal.o: md5.h
nat_traversal.o: crypto.h
nat_traversal.o: vendor.h
nat_traversal.o: ike_alg.h
nat_traversal.o: nat_traversal.h
ocsp.o: constants.h
ocsp.o: defs.h
ocsp.o: log.h
ocsp.o: x509.h
ocsp.o: crl.h
ocsp.o: ca.h
ocsp.o: rnd.h
ocsp.o: asn1.h
ocsp.o: certs.h
ocsp.o: smartcard.h
ocsp.o: oid.h
ocsp.o: whack.h
ocsp.o: pkcs1.h
ocsp.o: keys.h
ocsp.o: fetch.h
ocsp.o: ocsp.h
oid.o: oid.h
packet.o: constants.h
packet.o: defs.h
packet.o: log.h
packet.o: packet.h
packet.o: whack.h
pem.o: constants.h
pem.o: defs.h
pem.o: log.h
pem.o: md5.h
pem.o: whack.h
pem.o: pem.h
pgp.o: constants.h
pgp.o: defs.h
pgp.o: mp_defs.h
pgp.o: log.h
pgp.o: id.h
pgp.o: pgp.h
pgp.o: certs.h
pgp.o: md5.h
pgp.o: whack.h
pgp.o: pkcs1.h
pgp.o: keys.h
pkcs1.o: constants.h
pkcs1.o: defs.h
pkcs1.o: mp_defs.h
pkcs1.o: asn1.h
pkcs1.o: oid.h
pkcs1.o: log.h
pkcs1.o: pkcs1.h
pkcs1.o: md2.h
pkcs1.o: md5.h
pkcs1.o: sha1.h
pkcs1.o: rnd.h
pkcs7.o: constants.h
pkcs7.o: defs.h
pkcs7.o: asn1.h
pkcs7.o: oid.h
pkcs7.o: log.h
pkcs7.o: x509.h
pkcs7.o: certs.h
pkcs7.o: pkcs7.h
pkcs7.o: rnd.h
plutomain.o: constants.h
plutomain.o: defs.h
plutomain.o: id.h
plutomain.o: ca.h
plutomain.o: certs.h
plutomain.o: ac.h
plutomain.o: connections.h
plutomain.o: foodgroups.h
plutomain.o: packet.h
plutomain.o: demux.h
plutomain.o: server.h
plutomain.o: kernel.h
plutomain.o: log.h
plutomain.o: keys.h
plutomain.o: adns.h
plutomain.o: dnskey.h
plutomain.o: rnd.h
plutomain.o: state.h
plutomain.o: ipsec_doi.h
plutomain.o: ocsp.h
plutomain.o: crl.h
plutomain.o: fetch.h
plutomain.o: sha1.h
plutomain.o: md5.h
plutomain.o: crypto.h
plutomain.o: virtual.h
plutomain.o: nat_traversal.h
primegen.o: constants.h
primegen.o: defs.h
primegen.o: log.h
primegen.o: rnd.h
primegen.o: gcryptfix.h
rcv_whack.o: constants.h
rcv_whack.o: defs.h
rcv_whack.o: id.h
rcv_whack.o: ca.h
rcv_whack.o: certs.h
rcv_whack.o: ac.h
rcv_whack.o: smartcard.h
rcv_whack.o: connections.h
rcv_whack.o: foodgroups.h
rcv_whack.o: whack.h
rcv_whack.o: packet.h
rcv_whack.o: demux.h
rcv_whack.o: state.h
rcv_whack.o: ipsec_doi.h
rcv_whack.o: kernel.h
rcv_whack.o: rcv_whack.h
rcv_whack.o: log.h
rcv_whack.o: keys.h
rcv_whack.o: adns.h
rcv_whack.o: dnskey.h
rcv_whack.o: server.h
rcv_whack.o: fetch.h
rcv_whack.o: ocsp.h
rcv_whack.o: crl.h
rcv_whack.o: kernel_alg.h
rcv_whack.o: ike_alg.h
rnd.o: sha1.h
rnd.o: constants.h
rnd.o: defs.h
rnd.o: rnd.h
rnd.o: log.h
rnd.o: timer.h
server.o: constants.h
server.o: defs.h
server.o: state.h
server.o: connections.h
server.o: kernel.h
server.o: log.h
server.o: server.h
server.o: timer.h
server.o: packet.h
server.o: demux.h
server.o: rcv_whack.h
server.o: rcv_info.h
server.o: keys.h
server.o: adns.h
server.o: dnskey.h
server.o: whack.h
server.o: kameipsec.h
server.o: nat_traversal.h
sha1.o: sha1.h
smallprime.o: constants.h
smallprime.o: defs.h
smallprime.o: gcryptfix.h
smartcard.o: constants.h
smartcard.o: rsaref/unix.h
smartcard.o: rsaref/pkcs11.h
smartcard.o: defs.h
smartcard.o: mp_defs.h
smartcard.o: log.h
smartcard.o: x509.h
smartcard.o: ca.h
smartcard.o: certs.h
smartcard.o: keys.h
smartcard.o: smartcard.h
smartcard.o: whack.h
smartcard.o: fetch.h
spdb.o: constants.h
spdb.o: defs.h
spdb.o: id.h
spdb.o: connections.h
spdb.o: state.h
spdb.o: packet.h
spdb.o: keys.h
spdb.o: kernel.h
spdb.o: log.h
spdb.o: spdb.h
spdb.o: whack.h
spdb.o: sha1.h
spdb.o: md5.h
spdb.o: crypto.h
spdb.o: alg_info.h
spdb.o: kernel_alg.h
spdb.o: ike_alg.h
spdb.o: db_ops.h
spdb.o: nat_traversal.h
state.o: constants.h
state.o: defs.h
state.o: connections.h
state.o: state.h
state.o: kernel.h
state.o: log.h
state.o: packet.h
state.o: keys.h
state.o: rnd.h
state.o: timer.h
state.o: whack.h
state.o: demux.h
state.o: ipsec_doi.h
state.o: sha1.h
state.o: md5.h
state.o: crypto.h
timer.o: constants.h
timer.o: defs.h
timer.o: connections.h
timer.o: state.h
timer.o: demux.h
timer.o: ipsec_doi.h
timer.o: kernel.h
timer.o: server.h
timer.o: log.h
timer.o: rnd.h
timer.o: timer.h
timer.o: whack.h
timer.o: nat_traversal.h
vendor.o: constants.h
vendor.o: defs.h
vendor.o: log.h
vendor.o: md5.h
vendor.o: connections.h
vendor.o: packet.h
vendor.o: demux.h
vendor.o: whack.h
vendor.o: vendor.h
vendor.o: kernel.h
vendor.o: nat_traversal.h
virtual.o: constants.h
virtual.o: defs.h
virtual.o: log.h
virtual.o: connections.h
virtual.o: whack.h
virtual.o: virtual.h
whack.o: constants.h
whack.o: defs.h
whack.o: whack.h
x509.o: constants.h
x509.o: defs.h
x509.o: mp_defs.h
x509.o: log.h
x509.o: id.h
x509.o: asn1.h
x509.o: oid.h
x509.o: pkcs1.h
x509.o: x509.h
x509.o: crl.h
x509.o: ca.h
x509.o: certs.h
x509.o: keys.h
x509.o: whack.h
x509.o: fetch.h
x509.o: ocsp.h
x509.o: sha1.h
