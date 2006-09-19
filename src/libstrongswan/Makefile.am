lib_LTLIBRARIES = libstrongswan.la

libstrongswan_la_SOURCES = \
definitions.c definitions.h \
types.c types.h \
library.c library.h \
asn1/oid.c asn1/oid.h \
asn1/asn1.c asn1/asn1.h \
asn1/pem.c asn1/pem.h \
asn1/ttodata.c asn1/ttodata.h \
crypto/rsa/rsa_private_key.c crypto/rsa/rsa_private_key.h \
crypto/rsa/rsa_public_key.h  crypto/rsa/rsa_public_key.c \
crypto/prfs/hmac_prf.c crypto/prfs/hmac_prf.h \
crypto/prfs/prf.c crypto/prfs/prf.h \
crypto/signers/hmac_signer.c crypto/signers/hmac_signer.h \
crypto/signers/signer.c crypto/signers/signer.h \
crypto/crypters/crypter.c crypto/crypters/crypter.h \
crypto/crypters/aes_cbc_crypter.c  crypto/crypters/aes_cbc_crypter.h\
crypto/crypters/des_crypter.c  crypto/crypters/des_crypter.h\
crypto/hashers/hasher.h crypto/hashers/hasher.c \
crypto/hashers/sha1_hasher.c crypto/hashers/sha1_hasher.h \
crypto/hashers/sha2_hasher.c crypto/hashers/sha2_hasher.h \
crypto/hashers/md5_hasher.c  crypto/hashers/md5_hasher.h \
crypto/prf_plus.h crypto/prf_plus.c \
crypto/hmac.c crypto/hmac.h \
crypto/certinfo.c crypto/certinfo.h \
crypto/x509.c crypto/x509.h \
crypto/crl.c crypto/crl.h \
crypto/diffie_hellman.c crypto/diffie_hellman.h \
utils/identification.c utils/identification.h \
utils/linked_list.c utils/linked_list.h utils/iterator.h\
utils/randomizer.c utils/randomizer.h \
utils/logger.c utils/logger.h \
utils/logger_manager.c utils/logger_manager.h \
utils/host.c utils/host.h \
utils/lexparser.c utils/lexparser.h \
utils/leak_detective.c utils/leak_detective.h \
utils/tester.c utils/tester.h

libstrongswan_la_LIBADD = -lgmp -lpthread

INCLUDES = -I$(top_srcdir)/src/libstrongswan
EXTRA_DIST = asn1/oid.txt asn1/oid.pl
BUILT_SOURCES = asn1/oid.c asn1/oid.h
MAINTAINERCLEANFILES = asn1/oid.c asn1/oid.h

if USE_LEAK_DETECTIVE
  libstrongswan_la_LIBADD += -ldl
  AM_CFLAGS = -DLEAK_DETECTIVE
endif

asn1/oid.c :	asn1/oid.txt asn1/oid.pl
		cd asn1 && $(PERL) oid.pl

asn1/oid.h :	asn1/oid.txt asn1/oid.pl
		cd asn1 && $(PERL) oid.pl
