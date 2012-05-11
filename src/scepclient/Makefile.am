ipsec_PROGRAMS = scepclient
scepclient_SOURCES = scepclient.c scep.c scep.h

scepclient.o :	$(top_builddir)/config.status

INCLUDES = \
-I$(top_srcdir)/src/libstrongswan \
-I$(top_srcdir)/src/libhydra

AM_CFLAGS = \
-DIPSEC_CONFDIR=\"${sysconfdir}\" \
-DPLUGINS=\""${scepclient_plugins}\""

scepclient_LDADD = \
$(top_builddir)/src/libstrongswan/libstrongswan.la

# This compile option activates smartcard support
if USE_SMARTCARD
  AM_CFLAGS += -DSMARTCARD
  scepclient_LDADD += $(DLLIB)
endif

dist_man_MANS = scepclient.8

