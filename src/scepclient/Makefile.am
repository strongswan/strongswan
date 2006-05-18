ipsec_PROGRAMS = scepclient
scepclient_SOURCES = rsakey.c rsakey.h pkcs10.c pkcs10.h scep.c scep.h scepclient.c

INCLUDES = -I$(top_srcdir)/src/libfreeswan -I$(top_srcdir)/src/pluto -I$(top_srcdir)/src/whack -I$(top_srcdir)/src/libcrypto
AM_CFLAGS = -DDEBUG -DNO_PLUTO -DIPSEC_CONFDIR=\"${confdir}\"
scepclient_LDADD = asn1.o ca.o crl.o certs.o constants.o defs.o fetch.o id.o \
                   keys.o lex.o md2.o md5.o mp_defs.o ocsp.o oid.o pem.o pgp.o \
                   pkcs1.o pkcs7.o rnd.o sha1.o smartcard.o x509.o loglite.o \
                   $(top_srcdir)/src/libfreeswan/libfreeswan.a $(top_srcdir)/src/libcrypto/libcrypto.a \
                   -lgmp

# This compile option activates smartcard support
if USE_SMARTCARD
  scepclient_LDADD += -ldl
endif

dist_man_MANS = scepclient.8

PLUTODIR=$(top_srcdir)/src/pluto
OPENACDIR=$(top_srcdir)/src/openac


loglite.o:	$(OPENACDIR)/loglite.c $(PLUTODIR)/log.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

asn1.o :	$(PLUTODIR)/asn1.c $(PLUTODIR)/asn1.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

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

md2.o :		$(PLUTODIR)/md2.c $(PLUTODIR)/md2.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

md5.o :		$(PLUTODIR)/md5.c $(PLUTODIR)/md5.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

ocsp.o :	$(PLUTODIR)/ocsp.c $(PLUTODIR)/ocsp.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

oid.o :		$(PLUTODIR)/oid.c $(PLUTODIR)/oid.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pem.o :		$(PLUTODIR)/pem.c $(PLUTODIR)/pem.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pgp.o :		$(PLUTODIR)/pgp.c $(PLUTODIR)/pgp.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pkcs1.o :	$(PLUTODIR)/pkcs1.c $(PLUTODIR)/pkcs1.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

pkcs7.o :	$(PLUTODIR)/pkcs7.c $(PLUTODIR)/pkcs7.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

rnd.o :		$(PLUTODIR)/rnd.c $(PLUTODIR)/rnd.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

sha1.o :	$(PLUTODIR)/sha1.c $(PLUTODIR)/sha1.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

smartcard.o :	$(PLUTODIR)/smartcard.c $(PLUTODIR)/smartcard.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

x509.o :	$(PLUTODIR)/x509.c $(PLUTODIR)/x509.h
		$(COMPILE) $(INCLUDES) -c -o $@ $<

# This compile option activates dynamic URL fetching using libcurl
if USE_LIBCURL
  scepclient_LDADD += -lcurl
endif
