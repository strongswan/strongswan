# Makefile.am was ported from the old Makefile the most
# painless way. Only the most important options are included,
# further work may be necessary here...

ipsec_PROGRAMS = pluto _pluto_adns

pluto_SOURCES = \
ac.c ac.h \
alg_info.c alg_info.h \
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
fetch.c fetch.h \
foodgroups.c foodgroups.h \
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
modecfg.c modecfg.h \
nat_traversal.c nat_traversal.h \
ocsp.c ocsp.h \
packet.c packet.h \
pem.c pem.h \
pgpcert.c pgpcert.h \
pkcs7.c pkcs7.h \
plutomain.c \
rcv_whack.c rcv_whack.h \
server.c server.h \
smartcard.c smartcard.h \
spdb.c spdb.h \
state.c state.h \
timer.c timer.h \
vendor.c vendor.h \
virtual.c virtual.h \
xauth.c xauth.h \
x509.c x509.h \
rsaref/pkcs11t.h rsaref/pkcs11.h rsaref/unix.h rsaref/pkcs11f.h

_pluto_adns_SOURCES = adns.c adns.h

LIBSTRONGSWANDIR=$(top_builddir)/src/libstrongswan
LIBFREESWANDIR=$(top_builddir)/src/libfreeswan

INCLUDES = \
-I${linuxdir} \
-I$(top_srcdir)/src/libstrongswan \
-I$(top_srcdir)/src/libfreeswan \
-I$(top_srcdir)/src/whack

AM_CFLAGS = \
-DIPSEC_DIR=\"${ipsecdir}\" \
-DIPSEC_CONFDIR=\"${confdir}\" \
-DIPSEC_PIDDIR=\"${piddir}\" \
-DSHARED_SECRETS_FILE=\"${confdir}/ipsec.secrets\" \
-DIPSEC_PLUGINDIR=\"${plugindir}\" \
-DPLUGINS=\""${pluto_plugins}\"" \
-DSTRONGSWAN_CONF=\"${strongswan_conf}\" \
-DKERNEL26_SUPPORT -DKERNEL26_HAS_KAME_DUPLICATES \
-DPLUTO -DKLIPS -DDEBUG

pluto_LDADD = \
$(LIBSTRONGSWANDIR)/libstrongswan.la \
$(LIBFREESWANDIR)/libfreeswan.a \
-lresolv -lpthread $(DLLIB)

_pluto_adns_LDADD = \
$(LIBFREESWANDIR)/libfreeswan.a \
-lresolv $(DLLIB)

dist_man_MANS = pluto.8 ipsec.secrets.5

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

# This compile option activates smartcard support
if USE_SMARTCARD
  AM_CFLAGS += -DSMARTCARD
endif

# This compile option activates the integrity test of libstrongswan
if USE_INTEGRITY_TEST
  AM_CFLAGS += -DINTEGRITY_TEST
endif

if USE_CAPABILITIES
  pluto_LDADD += -lcap
endif

if USE_THREADS
  AM_CFLAGS += -DTHREADS
endif
