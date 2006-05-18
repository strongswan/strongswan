lib_LTLIBRARIES = libstrongswan.la

libstrongswan_la_SOURCES = \
crypto/rsa/rsa_private_key.c crypto/rsa/rsa_public_key.h crypto/rsa/rsa_private_key.h crypto/rsa/rsa_public_key.c \
crypto/prfs/hmac_prf.c crypto/prfs/hmac_prf.h crypto/prfs/prf.c crypto/prfs/prf.h crypto/signers/hmac_signer.c \
crypto/signers/hmac_signer.h crypto/signers/signer.c crypto/signers/signer.h crypto/crypters/aes_cbc_crypter.c \
crypto/crypters/crypter.c crypto/crypters/aes_cbc_crypter.h crypto/crypters/crypter.h crypto/hashers/sha1_hasher.c \
crypto/hashers/md5_hasher.c crypto/hashers/hasher.h crypto/hashers/md5_hasher.h crypto/hashers/hasher.c \
crypto/hashers/sha1_hasher.h crypto/diffie_hellman.c crypto/prf_plus.h crypto/x509.c crypto/prf_plus.c \
crypto/hmac.c crypto/x509.h crypto/hmac.h crypto/diffie_hellman.h utils/identification.h utils/iterator.h \
utils/linked_list.c utils/linked_list.h utils/tester.c utils/leak_detective.c utils/logger_manager.c \
utils/randomizer.c utils/tester.h utils/leak_detective.h utils/host.c utils/logger_manager.h utils/randomizer.h \
utils/logger.c utils/host.h utils/logger.h utils/identification.c utils/lexparser.c utils/lexparser.h \
asn1/ttodata.c asn1/oid.h asn1/ttodata.h asn1/pem.c asn1/asn1.c asn1/pem.h asn1/asn1.h asn1/oid.c definitions.h types.h \
definitions.c library.c types.c library.h 

libstrongswan_la_LIBADD = -lgmp -lpthread

INCLUDES = -I$(top_srcdir)/src/libstrongswan
EXTRA_DIST = asn1/oid.txt asn1/oid.pl
