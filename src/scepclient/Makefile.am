ipsec_PROGRAMS = scepclient
scepclient_SOURCES = scepclient.c scep.c scep.h loglite.c

PLUTODIR=$(top_srcdir)/src/pluto
OPENACDIR=$(top_srcdir)/src/openac
WHACKDIR=$(top_srcdir)/src/whack
LIBFREESWANDIR=$(top_srcdir)/src/libfreeswan
LIBSTRONGSWANDIR=$(top_srcdir)/src/libstrongswan
LIBHYDRADIR=$(top_srcdir)/src/libhydra
LIBCRYPTODIR=$(top_srcdir)/src/libcrypto

INCLUDES = \
-I$(LIBFREESWANDIR) \
-I$(LIBSTRONGSWANDIR) \
-I$(LIBHYDRADIR) \
-I$(PLUTODIR) \
-I$(LIBCRYPTODIR) \
-I$(WHACKDIR)

AM_CFLAGS = \
-DIPSEC_CONFDIR=\"${sysconfdir}\" \
-DPLUGINS=\""${pluto_plugins}\"" \
-DDEBUG -DNO_PLUTO

LIBSTRONGSWANBUILDDIR=$(top_builddir)/src/libstrongswan
LIBFREESWANBUILDDIR=$(top_builddir)/src/libfreeswan

scepclient_LDADD = \
constants.o defs.o lex.o pkcs7.o \
$(LIBSTRONGSWANBUILDDIR)/libstrongswan.la \
$(LIBFREESWANBUILDDIR)/libfreeswan.a

# This compile option activates smartcard support
if USE_SMARTCARD
  AM_CFLAGS += -DSMARTCARD
  scepclient_LDADD += $(DLLIB)
endif

dist_man_MANS = scepclient.8

constants.o :	$(PLUTODIR)/constants.c $(PLUTODIR)/constants.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

defs.o : 	$(PLUTODIR)/defs.c $(PLUTODIR)/defs.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

lex.o :		$(PLUTODIR)/lex.c $(PLUTODIR)/lex.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pkcs7.o :	$(PLUTODIR)/pkcs7.c $(PLUTODIR)/pkcs7.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

