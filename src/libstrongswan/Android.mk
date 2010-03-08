LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
LOCAL_SRC_FILES := \
	library.c library.h \
	chunk.c chunk.h \
	debug.c debug.h \
	enum.c enum.h \
	settings.h settings.c \
	printf_hook.c printf_hook.h \
	asn1/asn1.c asn1/asn1.h \
	asn1/asn1_parser.c asn1/asn1_parser.h \
	asn1/oid.c asn1/oid.h \
	attributes/attributes.c attributes/attributes.h \
	attributes/attribute_provider.h attributes/attribute_handler.h \
	attributes/attribute_manager.c attributes/attribute_manager.h \
	crypto/crypters/crypter.c crypto/crypters/crypter.h \
	crypto/hashers/hasher.h crypto/hashers/hasher.c \
	crypto/pkcs9.c crypto/pkcs9.h \
	crypto/proposal/proposal_keywords.c crypto/proposal/proposal_keywords.h \
	crypto/prfs/prf.c crypto/prfs/prf.h \
	crypto/rngs/rng.c crypto/rngs/rng.h \
	crypto/prf_plus.h crypto/prf_plus.c \
	crypto/signers/signer.c crypto/signers/signer.h \
	crypto/crypto_factory.c crypto/crypto_factory.h \
	crypto/crypto_tester.c crypto/crypto_tester.h \
	crypto/diffie_hellman.c crypto/diffie_hellman.h \
	crypto/transform.c crypto/transform.h \
	credentials/credential_factory.c credentials/credential_factory.h \
	credentials/builder.c credentials/builder.h \
	credentials/keys/key_encoding.c credentials/keys/key_encoding.h \
	credentials/keys/private_key.c credentials/keys/private_key.h \
	credentials/keys/public_key.c credentials/keys/public_key.h \
	credentials/keys/shared_key.c credentials/keys/shared_key.h \
	credentials/certificates/certificate.c credentials/certificates/certificate.h \
	credentials/certificates/x509.h credentials/certificates/x509.c \
	credentials/certificates/ac.h \
	credentials/certificates/crl.h credentials/certificates/crl.c \
	credentials/certificates/pkcs10.h \
	credentials/certificates/ocsp_request.h \
	credentials/certificates/ocsp_response.h credentials/certificates/ocsp_response.c \
	credentials/certificates/pgp_certificate.h \
	credentials/ietf_attributes/ietf_attributes.c credentials/ietf_attributes/ietf_attributes.h \
	database/database.h database/database_factory.h database/database_factory.c \
	fetcher/fetcher.h fetcher/fetcher_manager.h fetcher/fetcher_manager.c \
	selectors/traffic_selector.c selectors/traffic_selector.h \
	threading/thread.h threading/thread.c \
	threading/thread_value.h threading/thread_value.c \
	threading/mutex.h threading/mutex.c threading/condvar.h  \
	threading/rwlock.h threading/rwlock.c \
	threading/lock_profiler.h \
	utils.h utils.c \
	utils/host.c utils/host.h \
	utils/identification.c utils/identification.h \
	utils/iterator.h \
	utils/lexparser.c utils/lexparser.h \
	utils/linked_list.c utils/linked_list.h \
	utils/hashtable.c utils/hashtable.h \
	utils/enumerator.c utils/enumerator.h \
	utils/optionsfrom.c utils/optionsfrom.h \
	utils/backtrace.c utils/backtrace.h \
	plugins/plugin_loader.c plugins/plugin_loader.h plugins/plugin.h

# adding the plugin source files (copy-n-paste from their Makefile.am)

LOCAL_SRC_FILES += $(call add_plugin, aes, \
	aes_plugin.h aes_plugin.c aes_crypter.c aes_crypter.h \
)

LOCAL_SRC_FILES += $(call add_plugin, des, \
	des_plugin.h des_plugin.c des_crypter.c des_crypter.h \
)

LOCAL_SRC_FILES += $(call add_plugin, fips-prf, \
	fips_prf_plugin.h fips_prf_plugin.c fips_prf.c fips_prf.h \
)

LOCAL_SRC_FILES += $(call add_plugin, gmp, \
	gmp_plugin.h gmp_plugin.c \
	gmp_diffie_hellman.c gmp_diffie_hellman.h \
	gmp_rsa_private_key.c gmp_rsa_private_key.h \
	gmp_rsa_public_key.c gmp_rsa_public_key.h \
)
ifneq ($(call plugin_enabled, gmp)),)
LOCAL_C_INCLUDES += $(libgmp_PATH)
LOCAL_STATIC_LIBRARIES += libgmp
endif

LOCAL_SRC_FILES += $(call add_plugin, hmac, \
	hmac_plugin.h hmac_plugin.c hmac.h hmac.c \
	hmac_prf.h hmac_prf.c hmac_signer.h hmac_signer.c \
)

LOCAL_SRC_FILES += $(call add_plugin, md4, \
	md4_plugin.h md4_plugin.c md4_hasher.c md4_hasher.h \
)

LOCAL_SRC_FILES += $(call add_plugin, md5, \
	md5_plugin.h md5_plugin.c md5_hasher.c md5_hasher.h \
)

LOCAL_SRC_FILES += $(call add_plugin, openssl, \
	openssl_plugin.h openssl_plugin.c \
	openssl_util.c openssl_util.h \
	openssl_crypter.c openssl_crypter.h \
	openssl_hasher.c openssl_hasher.h \
	openssl_sha1_prf.c openssl_sha1_prf.h \
	openssl_diffie_hellman.c openssl_diffie_hellman.h \
	openssl_rsa_private_key.c openssl_rsa_private_key.h \
	openssl_rsa_public_key.c openssl_rsa_public_key.h \
	openssl_ec_diffie_hellman.c openssl_ec_diffie_hellman.h \
	openssl_ec_private_key.c openssl_ec_private_key.h \
	openssl_ec_public_key.c openssl_ec_public_key.h \
)
ifneq ($(call plugin_enabled, openssl)),)
LOCAL_C_INCLUDES += external/openssl/include
LOCAL_SHARED_LIBRARIES += libcrypto
endif

LOCAL_SRC_FILES += $(call add_plugin, pem, \
	pem_plugin.h pem_plugin.c \
	pem_builder.c pem_builder.h \
)

LOCAL_SRC_FILES += $(call add_plugin, pkcs1, \
	pkcs1_plugin.h pkcs1_plugin.c \
	pkcs1_encoder.h pkcs1_encoder.c \
	pkcs1_builder.h pkcs1_builder.c \
)

LOCAL_SRC_FILES += $(call add_plugin, pubkey, \
	pubkey_plugin.h pubkey_plugin.c \
	pubkey_cert.h pubkey_cert.c \
)

LOCAL_SRC_FILES += $(call add_plugin, random, \
	random_plugin.h random_plugin.c \
	random_rng.c random_rng.h \
)

LOCAL_SRC_FILES += $(call add_plugin, sha1, \
	sha1_plugin.h sha1_plugin.c \
	sha1_hasher.c sha1_hasher.h sha1_prf.c sha1_prf.h \
)

LOCAL_SRC_FILES += $(call add_plugin, sha2, \
	sha2_plugin.h sha2_plugin.c sha2_hasher.c sha2_hasher.h \
)

LOCAL_SRC_FILES += $(call add_plugin, x509, \
	x509_plugin.h x509_plugin.c \
	x509_cert.h x509_cert.c \
	x509_crl.h x509_crl.c \
	x509_ac.h x509_ac.c \
	x509_pkcs10.h x509_pkcs10.c \
	x509_ocsp_request.h x509_ocsp_request.c \
	x509_ocsp_response.h x509_ocsp_response.c \
)

LOCAL_SRC_FILES += $(call add_plugin, xcbc, \
	xcbc_plugin.h xcbc_plugin.c xcbc.h xcbc.c \
	xcbc_prf.h xcbc_prf.c xcbc_signer.h xcbc_signer.c \
)

# build libstrongswan ----------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH)

LOCAL_CFLAGS := $(strongswan_CFLAGS) \
	-include $(LOCAL_PATH)/AndroidConfigLocal.h

LOCAL_MODULE := libstrongswan

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libdl

LOCAL_STATIC_LIBRARIES += libvstr

include $(BUILD_SHARED_LIBRARY)

