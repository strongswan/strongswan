ipsec_PROGRAMS = scepclient
scepclient_SOURCES = scepclient.c rsakey.c rsakey.h pkcs10.c pkcs10.h scep.c scep.h loglite.c 

PLUTODIR=$(top_srcdir)/src/pluto
OPENACDIR=$(top_srcdir)/src/openac
WHACKDIR=$(top_srcdir)/src/whack
LIBFREESWANDIR=$(top_srcdir)/src/libfreeswan
LIBSTRONGSWANDIR=$(top_srcdir)/src/libstrongswan
LIBCRYPTODIR=$(top_srcdir)/src/libcrypto

INCLUDES = \
-I$(LIBFREESWANDIR) \
-I$(LIBSTRONGSWANDIR) \
-I$(PLUTODIR) \
-I$(LIBCRYPTODIR) \
-I$(WHACKDIR)

AM_CFLAGS = \
-DIPSEC_CONFDIR=\"${confdir}\" \
-DIPSEC_PLUGINDIR=\"${plugindir}\" \
-DPLUGINS=\""${pluto_plugins}\"" \
-DSTRONGSWAN_CONF=\"${strongswan_conf}\" \
-DNO_CREDENTIAL_FACTORY \
-DDEBUG -DNO_PLUTO

LIBSTRONGSWANBUILDDIR=$(top_builddir)/src/libstrongswan
LIBFREESWANBUILDDIR=$(top_builddir)/src/libfreeswan
LIBCRYPTOBUILDDIR=$(top_builddir)/src/libcrypto

scepclient_LDADD = \
ca.o crl.o certs.o constants.o defs.o fetch.o id.o keys.o lex.o \
mp_defs.o ocsp.o pem.o pgp.o pkcs1.o pkcs7.o smartcard.o x509.o \
$(LIBSTRONGSWANBUILDDIR)/libstrongswan.la \
$(LIBFREESWANBUILDDIR)/libfreeswan.a \
-lgmp

# This compile option activates smartcard support
if USE_SMARTCARD
  AM_CFLAGS += -DSMARTCARD
  scepclient_LDADD += $(DLLIB)
endif

dist_man_MANS = scepclient.8

ca.o :		$(PLUTODIR)/ca.c $(PLUTODIR)/ca.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

certs.o :	$(PLUTODIR)/certs.c $(PLUTODIR)/certs.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

constants.o :	$(PLUTODIR)/constants.c $(PLUTODIR)/constants.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

crl.o : 	$(PLUTODIR)/crl.c $(PLUTODIR)/crl.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

defs.o : 	$(PLUTODIR)/defs.c $(PLUTODIR)/defs.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

mp_defs.o :	$(PLUTODIR)/mp_defs.c $(PLUTODIR)/mp_defs.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

fetch.o : 	$(PLUTODIR)/fetch.c $(PLUTODIR)/fetch.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

id.o : 		$(PLUTODIR)/id.c $(PLUTODIR)/id.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

keys.o :	$(PLUTODIR)/keys.c $(PLUTODIR)/keys.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

lex.o :		$(PLUTODIR)/lex.c $(PLUTODIR)/lex.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

ocsp.o :	$(PLUTODIR)/ocsp.c $(PLUTODIR)/ocsp.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pem.o :		$(PLUTODIR)/pem.c $(PLUTODIR)/pem.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pgp.o :		$(PLUTODIR)/pgp.c $(PLUTODIR)/pgp.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pkcs1.o :	$(PLUTODIR)/pkcs1.c $(PLUTODIR)/pkcs1.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pkcs7.o :	$(PLUTODIR)/pkcs7.c $(PLUTODIR)/pkcs7.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

smartcard.o :	$(PLUTODIR)/smartcard.c $(PLUTODIR)/smartcard.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

x509.o :	$(PLUTODIR)/x509.c $(PLUTODIR)/x509.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<
