LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

strongswan_CHARON_PLUGINS := android-log openssl fips-prf random nonce pubkey \
	pkcs1 pem xcbc hmac socket-default \
	eap-identity eap-mschapv2 eap-md5

strongswan_PLUGINS := $(strongswan_CHARON_PLUGINS)

include $(LOCAL_PATH)/strongswan/Android.common.mk

# includes
strongswan_PATH := $(LOCAL_PATH)/strongswan
libvstr_PATH := $(LOCAL_PATH)/vstr/include
openssl_PATH := $(LOCAL_PATH)/openssl/include

# CFLAGS (partially from a configure run using droid-gcc)
strongswan_CFLAGS := \
	-Wno-format \
	-Wno-pointer-sign \
	-Wno-pointer-arith \
	-Wno-sign-compare \
	-Wno-strict-aliasing \
	-DHAVE___BOOL \
	-DHAVE_STDBOOL_H \
	-DHAVE_ALLOCA_H \
	-DHAVE_ALLOCA \
	-DHAVE_CLOCK_GETTIME \
	-DHAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC \
	-DHAVE_PRCTL \
	-DHAVE_LINUX_UDP_H \
	-DHAVE_STRUCT_SADB_X_POLICY_SADB_X_POLICY_PRIORITY \
	-DHAVE_IPSEC_MODE_BEET \
	-DHAVE_IPSEC_DIR_FWD \
	-DOPENSSL_NO_EC \
	-DOPENSSL_NO_ECDSA \
	-DOPENSSL_NO_ECDH \
	-DOPENSSL_NO_ENGINE \
	-DCONFIG_H_INCLUDED \
	-DCAPABILITIES \
	-DCAPABILITIES_NATIVE \
	-DMONOLITHIC \
	-DUSE_IKEV1 \
	-DUSE_IKEV2 \
	-DUSE_VSTR \
	-DDEBUG \
	-DCHARON_UDP_PORT=4000 \
	-DVERSION=\"$(strongswan_VERSION)\" \
	-DDEV_RANDOM=\"/dev/random\" \
	-DDEV_URANDOM=\"/dev/urandom\"

# only for Android 2.0+
strongswan_CFLAGS += \
	-DHAVE_IN6ADDR_ANY

include $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, \
		vstr \
		openssl \
		strongswan/src/libcharon \
		strongswan/src/libhydra \
		strongswan/src/libstrongswan \
))
