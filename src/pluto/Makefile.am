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
library.c library.h \
log.c log.h \
md2.c md2.h \
md5.c md5.h \
modecfg.c modecfg.h \
mp_defs.c mp_defs.h \
nat_traversal.c nat_traversal.h \
ocsp.c ocsp.h \
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
rsaref/pkcs11t.h rsaref/pkcs11.h rsaref/unix.h rsaref/pkcs11f.h

_pluto_adns_SOURCES = adns.c adns.h

LIBSTRONGSWANDIR=$(top_srcdir)/src/libstrongswan
LIBFREESWANDIR=$(top_builddir)/src/libfreeswan
LIBCRYPTODIR=$(top_builddir)/src/libcrypto


INCLUDES = \
-I${linuxdir} \
-I$(LIBSTRONGSWANDIR)\
-I$(top_srcdir)/src/libfreeswan \
-I$(top_srcdir)/src/libcrypto \
-I$(top_srcdir)/src/whack

AM_CFLAGS = \
-DIPSEC_DIR=\"${ipsecdir}\" \
-DIPSEC_CONFDIR=\"${confdir}\" \
-DIPSEC_PIDDIR=\"${piddir}\" \
-DSHARED_SECRETS_FILE=\"${confdir}/ipsec.secrets\" \
-DSTRONGSWAN_CONF=\"${strongswan_conf}\" \
-DKERNEL26_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES \
-DPLUTO -DKLIPS -DDEBUG

pluto_LDADD = \
oid.o debug.o linked_list.o enumerator.o settings.o \
$(LIBFREESWANDIR)/libfreeswan.a \
$(LIBCRYPTODIR)/libcrypto.a \
-lgmp -lresolv -lpthread -ldl

if USE_LEAK_DETECTIVE
  AM_CFLAGS += -DLEAK_DETECTIVE
  pluto_LDADD += backtrace.o leak_detective.o
endif

_pluto_adns_LDADD = \
$(LIBFREESWANDIR)/libfreeswan.a \
-lresolv -ldl

dist_man_MANS = pluto.8 ipsec.secrets.5

# Copy functions from libstrongswan
oid.o :	$(LIBSTRONGSWANDIR)/asn1/oid.c $(LIBSTRONGSWANDIR)/asn1/oid.h
		$(COMPILE) -c -o $@ $<

debug.o : $(LIBSTRONGSWANDIR)/debug.c $(LIBSTRONGSWANDIR)/debug.h
		$(COMPILE) -c -o $@ $<

backtrace.o : $(LIBSTRONGSWANDIR)/utils/backtrace.c $(LIBSTRONGSWANDIR)/utils/backtrace.h
		$(COMPILE) -c -o $@ $<

leak_detective.o : $(LIBSTRONGSWANDIR)/utils/leak_detective.c $(LIBSTRONGSWANDIR)/utils/leak_detective.h
		$(COMPILE) -c -o $@ $<

linked_list.o : $(LIBSTRONGSWANDIR)/utils/linked_list.c $(LIBSTRONGSWANDIR)/utils/linked_list.h
		$(COMPILE) -c -o $@ $<

enumerator.o : $(LIBSTRONGSWANDIR)/utils/enumerator.c $(LIBSTRONGSWANDIR)/utils/enumerator.h
		$(COMPILE) -c -o $@ $<

settings.o : $(LIBSTRONGSWANDIR)/settings.c $(LIBSTRONGSWANDIR)/settings.h
		$(COMPILE) -c -o $@ $<

# This compile option activates the sending of a strongSwan VID
if USE_VENDORID
  AM_CFLAGS += -DVENDORID
endif

# This compile option activates the sending of the XAUTH VID
if USE_XAUTH_VID
  AM_CFLAGS += -DXAUTH_VID
endif

# This compile option activates the support of the Cisco VPN client
if USE_CISCO_QUIRKS
  AM_CFLAGS += -DCISCO_QUIRKS
endif

# This compile option activates NAT traversal with IPSec transport mode
if USE_NAT_TRANSPORT
  AM_CFLAGS += -DI_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
endif

# This compile option activates dynamic URL fetching using libcurl
if USE_CURL
  pluto_LDADD += -lcurl
  AM_CFLAGS += -DLIBCURL
endif

# This compile option activates dynamic LDAP CRL fetching
if USE_LDAP
  pluto_LDADD += -lldap -llber
  AM_CFLAGS += -DLIBLDAP
endif

# This compile option activates smartcard support
if USE_SMARTCARD
  AM_CFLAGS += -DSMARTCARD
endif

if USE_CAPABILITIES
  pluto_LDADD += -lcap
endif

if USE_THREADS
  AM_CFLAGS += -DTHREADS
endif
