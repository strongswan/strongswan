lib_LTLIBRARIES = libstrongswan.la libstrongswan-lite.la

if USE_INTEGRITY_TEST
  libstrongswan_la_SOURCES = \
  fips/fips_canister_start.c \
  fips/fips.c fips/fips.h
else
  libstrongswan_la_SOURCES =
endif

libstrongswan_la_SOURCES += \
library.c library.h \
chunk.c chunk.h \
debug.c debug.h \
enum.c enum.h \
settings.h settings.c \
printf_hook.c printf_hook.h \
asn1/asn1.c asn1/asn1.h \
asn1/asn1_parser.c asn1/asn1_parser.h \
asn1/oid.c asn1/oid.h \
asn1/pem.c asn1/pem.h \
crypto/crypters/crypter.c crypto/crypters/crypter.h \
crypto/hashers/hasher.h crypto/hashers/hasher.c \
crypto/pkcs9.c crypto/pkcs9.h \
crypto/prfs/prf.c crypto/prfs/prf.h \
crypto/rngs/rng.c crypto/rngs/rng.h \
crypto/prf_plus.h crypto/prf_plus.c \
crypto/signers/signer.c crypto/signers/signer.h \
crypto/diffie_hellman.c crypto/diffie_hellman.h \
crypto/crypto_factory.c crypto/crypto_factory.h \
credentials/credential_factory.c credentials/credential_factory.h \
credentials/builder.c credentials/builder.h \
credentials/keys/private_key.c credentials/keys/private_key.h \
credentials/keys/public_key.c credentials/keys/public_key.h \
credentials/keys/shared_key.c credentials/keys/shared_key.h \
credentials/certificates/certificate.c credentials/certificates/certificate.h \
credentials/certificates/x509.h credentials/certificates/x509.c \
credentials/certificates/ac.h \
credentials/certificates/crl.h credentials/certificates/crl.c \
credentials/certificates/ocsp_request.h \
credentials/certificates/ocsp_response.h credentials/certificates/ocsp_response.c \
fetcher/fetcher.h fetcher/fetcher_manager.h fetcher/fetcher_manager.c \
database/database.h database/database_factory.h database/database_factory.c \
utils.h utils.c \
utils/host.c utils/host.h \
utils/identification.c utils/identification.h \
utils/iterator.h \
utils/lexparser.c utils/lexparser.h \
utils/linked_list.c utils/linked_list.h \
utils/hashtable.c utils/hashtable.h \
utils/enumerator.c utils/enumerator.h \
utils/optionsfrom.c utils/optionsfrom.h \
utils/mutex.c utils/mutex.h \
utils/backtrace.c utils/backtrace.h \
plugins/plugin_loader.c plugins/plugin_loader.h plugins/plugin.h

libstrongswan_la_LIBADD = -lpthread -ldl

libstrongswan_lite_la_SOURCES = \
chunk.c chunk.h \
debug.c debug.h \
asn1/oid.c asn1/oid.h \
printf_hook.c printf_hook.h \
settings.c settings.h \
utils.c utils.h \
utils/enumerator.c utils/enumerator.h \
utils/linked_list.c utils/linked_list.h

INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = -DIPSEC_DIR=\"${ipsecdir}\" \
			-DIPSEC_PLUGINDIR=\"${plugindir}\"

if USE_LEAK_DETECTIVE
  AM_CFLAGS += -DLEAK_DETECTIVE
  libstrongswan_la_SOURCES += \
    utils/leak_detective.c utils/leak_detective.h
  libstrongswan_lite_la_SOURCES += \
    utils/leak_detective.c utils/leak_detective.h \
    utils/backtrace.c utils/backtrace.h 
endif

if USE_LOCK_PROFILER
  AM_CFLAGS += -DLOCK_PROFILER
endif

if USE_INTEGRITY_TEST
  libstrongswan_la_SOURCES += \
  fips/fips_canister_end.c
endif

if USE_VSTR
  libstrongswan_la_LIBADD += -lvstr
endif

EXTRA_DIST = asn1/oid.txt asn1/oid.pl
BUILT_SOURCES = asn1/oid.c asn1/oid.h
MAINTAINERCLEANFILES = asn1/oid.c asn1/oid.h

asn1/oid.c :	asn1/oid.pl asn1/oid.txt
		(cd `dirname $<` && $(PERL) `basename $<`)

asn1/oid.h :	asn1/oid.pl asn1/oid.txt
		(cd `dirname $<` && $(PERL) `basename $<`)


# build plugins with their own Makefile
#######################################

SUBDIRS = .

if USE_AES
  SUBDIRS += plugins/aes
endif

if USE_DES
  SUBDIRS += plugins/des
endif

if USE_MD4
  SUBDIRS += plugins/md4
endif

if USE_MD5
  SUBDIRS += plugins/md5
endif

if USE_SHA1
  SUBDIRS += plugins/sha1
endif

if USE_SHA2
  SUBDIRS += plugins/sha2
endif

if USE_FIPS_PRF
  SUBDIRS += plugins/fips_prf
endif

if USE_GMP
  SUBDIRS += plugins/gmp
endif

if USE_RANDOM
  SUBDIRS += plugins/random
endif

if USE_HMAC
  SUBDIRS += plugins/hmac
endif

if USE_XCBC
  SUBDIRS += plugins/xcbc
endif

if USE_X509
  SUBDIRS += plugins/x509
endif

if USE_PUBKEY
  SUBDIRS += plugins/pubkey
endif

if USE_CURL
  SUBDIRS += plugins/curl
endif

if USE_LDAP
  SUBDIRS += plugins/ldap
endif

if USE_MYSQL
  SUBDIRS += plugins/mysql
endif

if USE_SQLITE
  SUBDIRS += plugins/sqlite
endif

if USE_PADLOCK
  SUBDIRS += plugins/padlock
endif

if USE_OPENSSL
  SUBDIRS += plugins/openssl
endif

if USE_AGENT
  SUBDIRS += plugins/agent
endif

if USE_INTEGRITY_TEST
  SUBDIRS += fips
endif
