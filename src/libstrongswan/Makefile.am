ipseclib_LTLIBRARIES = libstrongswan.la

libstrongswan_la_SOURCES = \
library.c chunk.c debug.c enum.c settings.c printf_hook.c asn1/asn1.c \
asn1/asn1_parser.c asn1/oid.c bio/bio_reader.c bio/bio_writer.c \
crypto/crypters/crypter.c crypto/hashers/hasher.c crypto/pkcs7.c crypto/pkcs9.c \
crypto/proposal/proposal_keywords.c crypto/proposal/proposal_keywords_static.c \
crypto/prfs/prf.c crypto/prfs/mac_prf.c \
crypto/rngs/rng.c crypto/prf_plus.c crypto/signers/signer.c \
crypto/signers/mac_signer.c crypto/crypto_factory.c crypto/crypto_tester.c \
crypto/diffie_hellman.c crypto/aead.c crypto/transform.c \
credentials/credential_factory.c credentials/builder.c \
credentials/cred_encoding.c credentials/keys/private_key.c \
credentials/keys/public_key.c credentials/keys/shared_key.c \
credentials/certificates/certificate.c credentials/certificates/crl.c \
credentials/certificates/ocsp_response.c \
credentials/ietf_attributes/ietf_attributes.c credentials/credential_manager.c \
credentials/sets/auth_cfg_wrapper.c credentials/sets/ocsp_response_wrapper.c \
credentials/sets/cert_cache.c credentials/sets/mem_cred.c \
credentials/sets/callback_cred.c credentials/auth_cfg.c database/database.c \
database/database_factory.c fetcher/fetcher.c fetcher/fetcher_manager.c eap/eap.c \
ipsec/ipsec_types.c \
pen/pen.c plugins/plugin_loader.c plugins/plugin_feature.c processing/jobs/job.c \
processing/jobs/callback_job.c processing/processor.c processing/scheduler.c \
selectors/traffic_selector.c threading/thread.c threading/thread_value.c \
threading/mutex.c threading/semaphore.c threading/rwlock.c threading/spinlock.c \
utils.c utils/host.c utils/packet.c utils/identification.c utils/lexparser.c \
utils/linked_list.c utils/blocking_queue.c utils/hashtable.c utils/enumerator.c \
utils/optionsfrom.c utils/capabilities.c utils/backtrace.c utils/tun_device.c

if USE_DEV_HEADERS
strongswan_includedir = ${dev_headers}
nobase_strongswan_include_HEADERS = \
library.h chunk.h debug.h enum.h settings.h printf_hook.h \
asn1/asn1.h asn1/asn1_parser.h asn1/oid.h bio/bio_reader.h bio/bio_writer.h \
crypto/crypters/crypter.h crypto/hashers/hasher.h crypto/mac.h \
crypto/pkcs7.h crypto/pkcs9.h crypto/proposal/proposal_keywords.h \
crypto/proposal/proposal_keywords_static.h \
crypto/prfs/prf.h crypto/prfs/mac_prf.h crypto/rngs/rng.h crypto/nonce_gen.h \
crypto/prf_plus.h crypto/signers/signer.h crypto/signers/mac_signer.h \
crypto/crypto_factory.h crypto/crypto_tester.h crypto/diffie_hellman.h \
crypto/aead.h crypto/transform.h \
credentials/credential_factory.h credentials/builder.h \
credentials/cred_encoding.h credentials/keys/private_key.h \
credentials/keys/public_key.h credentials/keys/shared_key.h \
credentials/certificates/certificate.h credentials/certificates/x509.h \
credentials/certificates/ac.h credentials/certificates/crl.h \
credentials/certificates/pkcs10.h credentials/certificates/ocsp_request.h \
credentials/certificates/ocsp_response.h \
credentials/certificates/pgp_certificate.h \
credentials/ietf_attributes/ietf_attributes.h \
credentials/credential_manager.h credentials/sets/auth_cfg_wrapper.h \
credentials/sets/ocsp_response_wrapper.h credentials/sets/cert_cache.h \
credentials/sets/mem_cred.h credentials/sets/callback_cred.h \
credentials/auth_cfg.h credentials/credential_set.h credentials/cert_validator.h \
database/database.h database/database_factory.h fetcher/fetcher.h \
fetcher/fetcher_manager.h eap/eap.h pen/pen.h ipsec/ipsec_types.h \
plugins/plugin_loader.h plugins/plugin.h plugins/plugin_feature.h \
processing/jobs/job.h processing/jobs/callback_job.h processing/processor.h \
processing/scheduler.h selectors/traffic_selector.h \
threading/thread.h threading/thread_value.h \
threading/mutex.h threading/condvar.h threading/spinlock.h threading/semaphore.h \
threading/rwlock.h threading/rwlock_condvar.h threading/lock_profiler.h \
utils.h utils/host.h utils/packet.h utils/identification.h utils/lexparser.h \
utils/linked_list.h utils/blocking_queue.h utils/hashtable.h utils/enumerator.h \
utils/optionsfrom.h utils/capabilities.h utils/backtrace.h utils/tun_device.h \
utils/leak_detective.h integrity_checker.h
endif

library.lo :	$(top_builddir)/config.status

libstrongswan_la_LIBADD = $(PTHREADLIB) $(DLLIB) $(BTLIB) $(SOCKLIB) $(RTLIB) $(BFDLIB)

INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
-DIPSEC_DIR=\"${ipsecdir}\" \
-DIPSEC_LIB_DIR=\"${ipseclibdir}\" \
-DPLUGINDIR=\"${plugindir}\" \
-DSTRONGSWAN_CONF=\"${strongswan_conf}\"

if USE_LEAK_DETECTIVE
  AM_CFLAGS += -DLEAK_DETECTIVE
  libstrongswan_la_SOURCES += utils/leak_detective.c
endif

if USE_LOCK_PROFILER
  AM_CFLAGS += -DLOCK_PROFILER
endif

if USE_INTEGRITY_TEST
  AM_CFLAGS += -DINTEGRITY_TEST
  libstrongswan_la_SOURCES += integrity_checker.c
endif

if USE_VSTR
  libstrongswan_la_LIBADD += -lvstr
endif

if USE_LIBCAP
  libstrongswan_la_LIBADD += -lcap
endif

EXTRA_DIST = \
asn1/oid.txt asn1/oid.pl \
crypto/proposal/proposal_keywords_static.txt \
Android.mk AndroidConfigLocal.h

BUILT_SOURCES = \
$(srcdir)/asn1/oid.c $(srcdir)/asn1/oid.h \
$(srcdir)/crypto/proposal/proposal_keywords_static.c

MAINTAINERCLEANFILES = \
$(srcdir)/asn1/oid.c $(srcdir)/asn1/oid.h \
$(srcdir)/crypto/proposal/proposal_keywords_static.c

$(srcdir)/asn1/oid.c :	$(srcdir)/asn1/oid.pl $(srcdir)/asn1/oid.txt
		(cd $(srcdir)/asn1/ && $(PERL) oid.pl)

$(srcdir)/asn1/oid.h :	$(srcdir)/asn1/oid.pl $(srcdir)/asn1/oid.txt
		(cd $(srcdir)/asn1/ && $(PERL) oid.pl)

$(srcdir)/crypto/proposal/proposal_keywords_static.c:	$(srcdir)/crypto/proposal/proposal_keywords_static.txt \
														$(srcdir)/crypto/proposal/proposal_keywords_static.h
		$(GPERF) -N proposal_get_token_static -m 10 -C -G -c -t -D < \
												$(srcdir)/crypto/proposal/proposal_keywords_static.txt > $@


# build plugins with their own Makefile
#######################################

if MONOLITHIC
SUBDIRS =
else
SUBDIRS = .
endif

if USE_AF_ALG
  SUBDIRS += plugins/af_alg
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/af_alg/libstrongswan-af-alg.la
endif
endif

if USE_AES
  SUBDIRS += plugins/aes
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/aes/libstrongswan-aes.la
endif
endif

if USE_DES
  SUBDIRS += plugins/des
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/des/libstrongswan-des.la
endif
endif

if USE_BLOWFISH
  SUBDIRS += plugins/blowfish
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/blowfish/libstrongswan-blowfish.la
endif
endif

if USE_MD4
  SUBDIRS += plugins/md4
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/md4/libstrongswan-md4.la
endif
endif

if USE_MD5
  SUBDIRS += plugins/md5
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/md5/libstrongswan-md5.la
endif
endif

if USE_SHA1
  SUBDIRS += plugins/sha1
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/sha1/libstrongswan-sha1.la
endif
endif

if USE_SHA2
  SUBDIRS += plugins/sha2
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/sha2/libstrongswan-sha2.la
endif
endif

if USE_GMP
  SUBDIRS += plugins/gmp
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/gmp/libstrongswan-gmp.la
endif
endif

if USE_RANDOM
  SUBDIRS += plugins/random
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/random/libstrongswan-random.la
endif
endif

if USE_NONCE
  SUBDIRS += plugins/nonce
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/nonce/libstrongswan-nonce.la
endif
endif

if USE_HMAC
  SUBDIRS += plugins/hmac
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/hmac/libstrongswan-hmac.la
endif
endif

if USE_CMAC
  SUBDIRS += plugins/cmac
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/cmac/libstrongswan-cmac.la
endif
endif

if USE_XCBC
  SUBDIRS += plugins/xcbc
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/xcbc/libstrongswan-xcbc.la
endif
endif

if USE_X509
  SUBDIRS += plugins/x509
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/x509/libstrongswan-x509.la
endif
endif

if USE_REVOCATION
  SUBDIRS += plugins/revocation
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/revocation/libstrongswan-revocation.la
endif
endif

if USE_CONSTRAINTS
  SUBDIRS += plugins/constraints
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/constraints/libstrongswan-constraints.la
endif
endif

if USE_PUBKEY
  SUBDIRS += plugins/pubkey
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/pubkey/libstrongswan-pubkey.la
endif
endif

if USE_PKCS1
  SUBDIRS += plugins/pkcs1
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/pkcs1/libstrongswan-pkcs1.la
endif
endif

if USE_PKCS8
  SUBDIRS += plugins/pkcs8
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/pkcs8/libstrongswan-pkcs8.la
endif
endif

if USE_PGP
  SUBDIRS += plugins/pgp
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/pgp/libstrongswan-pgp.la
endif
endif

if USE_DNSKEY
  SUBDIRS += plugins/dnskey
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/dnskey/libstrongswan-dnskey.la
endif
endif

if USE_PEM
  SUBDIRS += plugins/pem
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/pem/libstrongswan-pem.la
endif
endif

if USE_CURL
  SUBDIRS += plugins/curl
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/curl/libstrongswan-curl.la
endif
endif

if USE_SOUP
  SUBDIRS += plugins/soup
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/soup/libstrongswan-soup.la
endif
endif

if USE_LDAP
  SUBDIRS += plugins/ldap
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/ldap/libstrongswan-ldap.la
endif
endif

if USE_MYSQL
  SUBDIRS += plugins/mysql
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/mysql/libstrongswan-mysql.la
endif
endif

if USE_SQLITE
  SUBDIRS += plugins/sqlite
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/sqlite/libstrongswan-sqlite.la
endif
endif

if USE_PADLOCK
  SUBDIRS += plugins/padlock
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/padlock/libstrongswan-padlock.la
endif
endif

if USE_OPENSSL
  SUBDIRS += plugins/openssl
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/openssl/libstrongswan-openssl.la
endif
endif

if USE_GCRYPT
  SUBDIRS += plugins/gcrypt
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/gcrypt/libstrongswan-gcrypt.la
endif
endif

if USE_FIPS_PRF
  SUBDIRS += plugins/fips_prf
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/fips_prf/libstrongswan-fips-prf.la
endif
endif

if USE_AGENT
  SUBDIRS += plugins/agent
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/agent/libstrongswan-agent.la
endif
endif

if USE_PKCS11
  SUBDIRS += plugins/pkcs11
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/pkcs11/libstrongswan-pkcs11.la
endif
endif

if USE_CTR
  SUBDIRS += plugins/ctr
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/ctr/libstrongswan-ctr.la
endif
endif

if USE_CCM
  SUBDIRS += plugins/ccm
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/ccm/libstrongswan-ccm.la
endif
endif

if USE_GCM
  SUBDIRS += plugins/gcm
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/gcm/libstrongswan-gcm.la
endif
endif

if USE_TEST_VECTORS
  SUBDIRS += plugins/test_vectors
if MONOLITHIC
  libstrongswan_la_LIBADD += plugins/test_vectors/libstrongswan-test-vectors.la
endif
endif
