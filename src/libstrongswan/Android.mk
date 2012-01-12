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
bio/bio_reader.h bio/bio_reader.c bio/bio_writer.h bio/bio_writer.c \
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
crypto/aead.c crypto/aead.h \
crypto/transform.c crypto/transform.h \
credentials/credential_factory.c credentials/credential_factory.h \
credentials/builder.c credentials/builder.h \
credentials/cred_encoding.c credentials/cred_encoding.h \
credentials/keys/private_key.c credentials/keys/private_key.h \
credentials/keys/public_key.c credentials/keys/public_key.h \
credentials/keys/shared_key.c credentials/keys/shared_key.h \
credentials/certificates/certificate.c credentials/certificates/certificate.h \
credentials/certificates/x509.h credentials/certificates/ac.h \
credentials/certificates/crl.h credentials/certificates/crl.c \
credentials/certificates/pkcs10.h \
credentials/certificates/ocsp_request.h \
credentials/certificates/ocsp_response.h credentials/certificates/ocsp_response.c \
credentials/certificates/pgp_certificate.h \
credentials/ietf_attributes/ietf_attributes.c credentials/ietf_attributes/ietf_attributes.h \
credentials/credential_manager.c credentials/credential_manager.h \
credentials/sets/auth_cfg_wrapper.c credentials/sets/auth_cfg_wrapper.h \
credentials/sets/ocsp_response_wrapper.c credentials/sets/ocsp_response_wrapper.h \
credentials/sets/cert_cache.c credentials/sets/cert_cache.h \
credentials/sets/mem_cred.c credentials/sets/mem_cred.h \
credentials/sets/callback_cred.c credentials/sets/callback_cred.h \
credentials/auth_cfg.c credentials/auth_cfg.h credentials/credential_set.h \
credentials/cert_validator.h database/database.h database/database.c \
database/database_factory.h database/database_factory.c \
fetcher/fetcher.h fetcher/fetcher.c fetcher/fetcher_manager.h fetcher/fetcher_manager.c \
eap/eap.h eap/eap.c \
pen/pen.h pen/pen.c \
plugins/plugin_loader.c plugins/plugin_loader.h plugins/plugin.h \
plugins/plugin_feature.c plugins/plugin_feature.h \
processing/jobs/job.h processing/jobs/job.c \
processing/jobs/callback_job.c processing/jobs/callback_job.h \
processing/processor.c processing/processor.h \
processing/scheduler.c processing/scheduler.h \
selectors/traffic_selector.c selectors/traffic_selector.h \
threading/thread.h threading/thread.c \
threading/thread_value.h threading/thread_value.c \
threading/mutex.h threading/mutex.c threading/condvar.h  \
threading/rwlock.h threading/rwlock.c \
threading/lock_profiler.h \
utils.h utils.c \
utils/host.c utils/host.h \
utils/identification.c utils/identification.h \
utils/lexparser.c utils/lexparser.h \
utils/linked_list.c utils/linked_list.h \
utils/hashtable.c utils/hashtable.h \
utils/enumerator.c utils/enumerator.h \
utils/optionsfrom.c utils/optionsfrom.h \
utils/backtrace.c utils/backtrace.h

# adding the plugin source files

LOCAL_SRC_FILES += $(call add_plugin, aes)

LOCAL_SRC_FILES += $(call add_plugin, des)

LOCAL_SRC_FILES += $(call add_plugin, fips-prf)

LOCAL_SRC_FILES += $(call add_plugin, gmp)
ifneq ($(call plugin_enabled, gmp),)
LOCAL_C_INCLUDES += $(libgmp_PATH)
LOCAL_SHARED_LIBRARIES += libgmp
endif

LOCAL_SRC_FILES += $(call add_plugin, hmac)

LOCAL_SRC_FILES += $(call add_plugin, md4)

LOCAL_SRC_FILES += $(call add_plugin, md5)

LOCAL_SRC_FILES += $(call add_plugin, openssl)
ifneq ($(call plugin_enabled, openssl),)
LOCAL_C_INCLUDES += external/openssl/include
LOCAL_SHARED_LIBRARIES += libcrypto
endif

LOCAL_SRC_FILES += $(call add_plugin, pem)

LOCAL_SRC_FILES += $(call add_plugin, pkcs1)

LOCAL_SRC_FILES += $(call add_plugin, pkcs11)

LOCAL_SRC_FILES += $(call add_plugin, pubkey)

LOCAL_SRC_FILES += $(call add_plugin, random)

LOCAL_SRC_FILES += $(call add_plugin, sha1)

LOCAL_SRC_FILES += $(call add_plugin, sha2)

LOCAL_SRC_FILES += $(call add_plugin, x509)

LOCAL_SRC_FILES += $(call add_plugin, xcbc)

# build libstrongswan ----------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH)

LOCAL_CFLAGS := $(strongswan_CFLAGS) \
	-include $(LOCAL_PATH)/AndroidConfigLocal.h

LOCAL_MODULE := libstrongswan

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libdl libvstr

include $(BUILD_SHARED_LIBRARY)

