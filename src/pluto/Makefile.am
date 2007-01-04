# Makefile.am was ported from the old Makefile the most
# painless way. Only the most important options are included,
# further work may be necessary here...

ipsec_PROGRAMS = pluto _pluto_adns

pluto_SOURCES = \
ac.c ac.h \
alg_info.c alg_info.h \
asn1.c asn1.h \
ca.c ca.h \
certs.c certs.h \
connections.c connections.h \
constants.c constants.h \
cookie.c cookie.h \
crl.c crl.h \
crypto.c crypto.h \
db_ops.c db_ops.h \
defs.c defs.h \
demux.c demux.h \
dnskey.c dnskey.h \
dsa.c dsa.h \
elgamal.c elgamal.h \
fetch.c fetch.h \
foodgroups.c foodgroups.h \
gcryptfix.c gcryptfix.h \
id.c id.h \
ike_alg.c ike_alg.h \
ipsec_doi.c ipsec_doi.h \
kameipsec.h \
kernel.c kernel.h \
kernel_alg.c kernel_alg.h \
kernel_netlink.c kernel_netlink.h \
kernel_noklips.c kernel_noklips.h \
kernel_pfkey.c kernel_pfkey.h \
keys.c keys.h \
lex.c lex.h \
log.c log.h \
md2.c md2.h \
md5.c md5.h \
modecfg.c modecfg.h \
mp_defs.c mp_defs.h \
nat_traversal.c nat_traversal.h \
ocsp.c ocsp.h \
oid.c oid.h \
packet.c packet.h \
pem.c pem.h \
pgp.c pgp.h \
pkcs1.c pkcs1.h \
pkcs7.c pkcs7.h \
plutomain.c \
primegen.c smallprime.c \
rcv_whack.c rcv_whack.h \
rnd.c rnd.h \
server.c server.h \
sha1.c sha1.h \
smartcard.c smartcard.h \
spdb.c spdb.h \
state.c state.h \
timer.c timer.h \
vendor.c vendor.h \
virtual.c virtual.h \
xauth.c xauth.h \
x509.c x509.h \
alg/ike_alg_aes.c alg/ike_alg_blowfish.c alg/ike_alg_twofish.c \
alg/ike_alg_serpent.c alg/ike_alg_sha2.c alg/ike_alginit.c \
linux26/netlink.h linux26/rtnetlink.h linux26/xfrm.h \
rsaref/pkcs11t.h rsaref/pkcs11.h rsaref/unix.h rsaref/pkcs11f.h

_pluto_adns_SOURCES = adns.c adns.h

INCLUDES = \
-I$(top_srcdir)/src/libfreeswan \
-I$(top_srcdir)/src/libcrypto \
-I$(top_srcdir)/src/whack

AM_CFLAGS = \
-DIPSEC_DIR=\"${ipsecdir}\" \
-DIPSEC_CONFDIR=\"${confdir}\" \
-DIPSEC_PIDDIR=\"${piddir}\" \
-DSHARED_SECRETS_FILE=\"${confdir}/ipsec.secrets\" \
-DKERNEL26_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES \
-DPLUTO -DKLIPS -DDEBUG \
-DVENDORID -DTHREADS

pluto_LDADD = \
$(top_srcdir)/src/libfreeswan/libfreeswan.a \
$(top_srcdir)/src/libcrypto/libcrypto.a \
-lgmp -lresolv -lpthread

_pluto_adns_LDADD = \
$(top_srcdir)/src/libfreeswan/libfreeswan.a \
-lresolv

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

