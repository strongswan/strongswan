# Makefile.am was ported from the old Makefile the most
# painless way. Only the most important options are included,
# further work may be necessary here...

ipsec_PROGRAMS = pluto

if USE_ADNS
ipsec_PROGRAMS += _pluto_adns
endif

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
event_queue.c event_queue.h \
fetch.c fetch.h \
foodgroups.c foodgroups.h \
ike_alg.c ike_alg.h \
ipsec_doi.c ipsec_doi.h \
kameipsec.h \
kernel.c kernel.h \
kernel_alg.c kernel_alg.h \
kernel_pfkey.c kernel_pfkey.h \
keys.c keys.h \
lex.c lex.h \
log.c log.h \
myid.c myid.h \
modecfg.c modecfg.h \
nat_traversal.c nat_traversal.h \
ocsp.c ocsp.h \
packet.c packet.h \
pkcs7.c pkcs7.h \
plugin_list.c plugin_list.h \
pluto.c pluto.h \
plutomain.c \
rcv_whack.c rcv_whack.h \
server.c server.h \
smartcard.c smartcard.h \
spdb.c spdb.h \
state.c state.h \
timer.c timer.h \
vendor.c vendor.h \
virtual.c virtual.h \
whack_attribute.c whack_attribute.h \
xauth/xauth_manager.c xauth/xauth_manager.h \
xauth/xauth_provider.h xauth/xauth_verifier.h \
x509.c x509.h \
builder.c builder.h \
rsaref/pkcs11t.h rsaref/pkcs11.h rsaref/unix.h rsaref/pkcs11f.h

if USE_ADNS
pluto_SOURCES += \
dnskey.c dnskey.h

_pluto_adns_SOURCES = \
adns.c adns.h
endif

plutomain.o :	$(top_builddir)/config.status

LIBSTRONGSWANDIR=$(top_builddir)/src/libstrongswan
LIBFREESWANDIR=$(top_builddir)/src/libfreeswan
LIBHYDRADIR=$(top_builddir)/src/libhydra

INCLUDES = \
-I${linux_headers} \
-I$(top_srcdir)/src/libstrongswan \
-I$(top_srcdir)/src/libfreeswan \
-I$(top_srcdir)/src/libhydra \
-I$(top_srcdir)/src/whack

AM_CFLAGS = -rdynamic \
-DIPSEC_DIR=\"${ipsecdir}\" \
-DIPSEC_CONFDIR=\"${sysconfdir}\" \
-DIPSEC_PIDDIR=\"${piddir}\" \
-DSHARED_SECRETS_FILE=\"${sysconfdir}/ipsec.secrets\" \
-DPLUGINS=\""${pluto_plugins}\"" \
-DPKCS11_DEFAULT_LIB=\"${default_pkcs11}\" \
-DKERNEL26_HAS_KAME_DUPLICATES \
-DPLUTO -DDEBUG

pluto_LDADD = \
$(LIBSTRONGSWANDIR)/libstrongswan.la \
$(LIBFREESWANDIR)/libfreeswan.a \
$(LIBHYDRADIR)/libhydra.la \
-lresolv $(PTHREADLIB) $(DLLIB)

if USE_ADNS
_pluto_adns_LDADD = \
$(LIBFREESWANDIR)/libfreeswan.a \
-lresolv $(DLLIB)
endif

dist_man_MANS = pluto.8

EXTRA_DIST = Android.mk

# compile options
#################

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

if USE_LIBCAP
  pluto_LDADD += -lcap
endif

if USE_THREADS
  AM_CFLAGS += -DTHREADS
endif

if USE_ADNS
  AM_CFLAGS += -DADNS
endif

# build optional plugins
########################

SUBDIRS = .

if USE_XAUTH
  SUBDIRS += plugins/xauth
endif

