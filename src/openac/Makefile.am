ipsec_PROGRAMS = openac
openac_SOURCES = openac.c build.c build.h loglite.c

INCLUDES = -I$(top_srcdir)/src/libfreeswan -I$(top_srcdir)/src/pluto -I$(top_srcdir)/src/libcrypto -I$(top_srcdir)/src/whack
AM_CFLAGS = -DDEBUG -DNO_PLUTO -DIPSEC_CONFDIR=\"${confdir}\"
openac_LDADD = ac.o asn1.o ca.o certs.o constants.o crl.o defs.o mp_defs.o fetch.o id.o keys.o lex.o \
               md2.o md5.o ocsp.o oid.o pem.o pgp.o pkcs1.o rnd.o sha1.o smartcard.o x509.o \
               $(top_srcdir)/src/libfreeswan/libfreeswan.a $(top_srcdir)/src/libcrypto/libcrypto.a \
               -lgmp

# This compile option activates smartcard support
if USE_SMARTCARD
  openac_LDADD += -ldl
endif

dist_man_MANS = openac.8

PLUTODIR=$(top_srcdir)/src/pluto

ac.o :		$(PLUTODIR)/ac.c $(PLUTODIR)/ac.h
		$(COMPILE) -c -o $@ $<

asn1.o :	$(PLUTODIR)/asn1.c $(PLUTODIR)/asn1.h
		$(COMPILE) -c -o $@ $<

ca.o :		$(PLUTODIR)/ca.c $(PLUTODIR)/ca.h
		$(COMPILE) -c -o $@ $<

certs.o :	$(PLUTODIR)/certs.c $(PLUTODIR)/certs.h
		$(COMPILE) -c -o $@ $<

constants.o :	$(PLUTODIR)/constants.c $(PLUTODIR)/constants.h
		$(COMPILE) -c -o $@ $<

crl.o : 	$(PLUTODIR)/crl.c $(PLUTODIR)/crl.h
		$(COMPILE) -c -o $@ $<

defs.o : 	$(PLUTODIR)/defs.c $(PLUTODIR)/defs.h
		$(COMPILE) -c -o $@ $<

mp_defs.o :	$(PLUTODIR)/mp_defs.c $(PLUTODIR)/mp_defs.h
		$(COMPILE) -c -o $@ $<

fetch.o : 	$(PLUTODIR)/fetch.c $(PLUTODIR)/fetch.h
		$(COMPILE) -c -o $@ $<

id.o : 		$(PLUTODIR)/id.c $(PLUTODIR)/id.h
		$(COMPILE) -c -o $@ $<

keys.o :	$(PLUTODIR)/keys.c $(PLUTODIR)/keys.h
		$(COMPILE) -c -o $@ $<

lex.o :		$(PLUTODIR)/lex.c $(PLUTODIR)/lex.h
		$(COMPILE) -c -o $@ $<

md2.o :		$(PLUTODIR)/md2.c $(PLUTODIR)/md2.h
		$(COMPILE) -c -o $@ $<

md5.o :		$(PLUTODIR)/md5.c $(PLUTODIR)/md5.h
		$(COMPILE) -c -o $@ $<

ocsp.o :	$(PLUTODIR)/ocsp.c $(PLUTODIR)/ocsp.h
		$(COMPILE) -c -o $@ $<

oid.o :		$(PLUTODIR)/oid.c $(PLUTODIR)/oid.h
		$(COMPILE) -c -o $@ $<

pem.o :		$(PLUTODIR)/pem.c $(PLUTODIR)/pem.h
		$(COMPILE) -c -o $@ $<

pgp.o :		$(PLUTODIR)/pgp.c $(PLUTODIR)/pgp.h
		$(COMPILE) -c -o $@ $<

pkcs1.o :	$(PLUTODIR)/pkcs1.c $(PLUTODIR)/pkcs1.h
		$(COMPILE) -c -o $@ $<

rnd.o :		$(PLUTODIR)/rnd.c $(PLUTODIR)/rnd.h
		$(COMPILE) -c -o $@ $<

sha1.o :	$(PLUTODIR)/sha1.c $(PLUTODIR)/sha1.h
		$(COMPILE) -c -o $@ $<

smartcard.o :	$(PLUTODIR)/smartcard.c $(PLUTODIR)/smartcard.h
		$(COMPILE) -c -o $@ $<

x509.o :	$(PLUTODIR)/x509.c $(PLUTODIR)/x509.h
		$(COMPILE) -c -o $@ $<

