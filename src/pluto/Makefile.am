# Makefile.am was ported from the old Makefile the most
# painless way. Only the most important options are included,
# further work may be necessary here...

ipsec_PROGRAMS = pluto _pluto_adns

pluto_SOURCES = \
oid.c oid.h linux26/rtnetlink.h linux26/xfrm.h linux26/netlink.h rsaref/pkcs11t.h rsaref/pkcs11.h \
rsaref/unix.h rsaref/pkcs11f.h alg/ike_alg_twofish.c alg/ike_alg_aes.c alg/ike_alg_blowfish.c \
alg/ike_alg_sha2.c alg/ike_alg_serpent.c alg/ike_alginit.c kernel_alg.c kernel_alg.h kernel_pfkey.h \
kernel_pfkey.c gcryptfix.c gcryptfix.h primegen.c smallprime.c ocsp.c ocsp.h pgp.c ac.c certs.c \
connections.c certs.h virtual.c connections.h fetch.c virtual.h fetch.h ipsec_doi.c ipsec_doi.h \
x509.c kameipsec.h cookie.c x509.h cookie.h pgp.h ac.h sha1.c sha1.h constants.c smartcard.c \
kernel.c constants.h smartcard.h kernel.h dnskey.c asn1.c dnskey.h elgamal.c db_ops.c asn1.h \
elgamal.h db_ops.h mp_defs.c state.c mp_defs.h ca.c state.h pkcs7.c lex.c ca.h \
pkcs7.h id.c lex.h id.h keys.c ike_alg.c keys.h md5.c md5.h kernel_noklips.c ike_alg.h rcv_whack.c \
rcv_whack.h alg_info.c alg_info.h pem.c kernel_noklips.h foodgroups.c pem.h kernel_netlink.c \
foodgroups.h vendor.c vendor.h packet.c packet.h crl.c md2.c rnd.c crl.h md2.h spdb.c rnd.h \
spdb.h modecfg.c timer.h nat_traversal.c server.c dsa.c plutomain.c modecfg.h kernel_netlink.h \
nat_traversal.h server.h dsa.h timer.c crypto.c pkcs1.c log.c defs.c demux.c crypto.h pkcs1.h \
log.h defs.h demux.h

_pluto_adns_SOURCES = adns.c adns.h

INCLUDES = -I$(top_srcdir)/src/libfreeswan -I$(top_srcdir)/src/libcrypto -I$(top_srcdir)/src/whack
AM_CFLAGS = -DIPSEC_DIR=\"${ipsecdir}\" -DIPSEC_CONFDIR=\"${confdir}\" -DIPSEC_PIDDIR=\"${piddir}\" \
-DDEBUG -DKERNEL26_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES -DPLUTO \
-DVENDORID -DSHARED_SECRETS_FILE=\"${confdir}/ipsec.secrets\" -DTHREADS -DKLIPS
pluto_LDADD = $(top_srcdir)/src/libfreeswan/libfreeswan.a $(top_srcdir)/src/libcrypto/libcrypto.a -lgmp -lresolv -lpthread
_pluto_adns_LDADD = -lresolv $(top_srcdir)/src/libfreeswan/libfreeswan.a
dist_man_MANS = pluto.8 ipsec.secrets.5
EXTRA_DIST = oid.pl oid.txt
BUILT_SOURCES = oid.c oid.h
MAINTAINERCLEANFILES = oid.c oid.h

oid.c:	oid.txt oid.pl
	$(PERL) oid.pl

oid.h:	oid.txt oid.pl
	$(PERL) oid.pl

# This compile option activates dynamic URL fetching using libcurl
if USE_LIBCURL
  pluto_LDADD += -lcurl
endif

# This compile option activates dynamic LDAP CRL fetching
if USE_LDAP
  pluto_LDADD += -lldap -llber
endif

# This compile option activates smartcard support
if USE_SMARTCARD
  pluto_LDADD += -ldl
endif

install-exec-local :
	mkdir -p -m 755 $(confdir)/ipsec.d
	mkdir -p -m 755 $(confdir)/ipsec.d/cacerts
	mkdir -p -m 755 $(confdir)/ipsec.d/ocspcerts
	mkdir -p -m 755 $(confdir)/ipsec.d/certs
	mkdir -p -m 755 $(confdir)/ipsec.d/acerts
	mkdir -p -m 755 $(confdir)/ipsec.d/aacerts
	mkdir -p -m 755 $(confdir)/ipsec.d/crls
	mkdir -p -m 755 $(confdir)/ipsec.d/reqs
	mkdir -p -m 700 $(confdir)/ipsec.d/private

