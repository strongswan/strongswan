LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
LOCAL_SRC_FILES := \
ac.c ac.h \
alg_info.c alg_info.h \
ca.c ca.h \
certs.c certs.h \
connections.c connections.h \
constants.c constants.h \
cookie.c cookie.h \
crl.c crl.h \
crypto.c crypto.h \
db_ops.c db_ops.h \
defs.c defs.h \
demux.c demux.h \
event_queue.c event_queue.h \
fetch.c fetch.h \
foodgroups.c foodgroups.h \
ike_alg.c ike_alg.h \
ipsec_doi.c ipsec_doi.h \
kameipsec.h \
kernel.c kernel.h \
kernel_alg.c kernel_alg.h \
kernel_pfkey.c kernel_pfkey.h \
keys.c keys.h \
lex.c lex.h \
log.c log.h \
myid.c myid.h \
modecfg.c modecfg.h \
nat_traversal.c nat_traversal.h \
ocsp.c ocsp.h \
packet.c packet.h \
pkcs7.c pkcs7.h \
plugin_list.c plugin_list.h \
pluto.c pluto.h \
plutomain.c \
rcv_whack.c rcv_whack.h \
server.c server.h \
smartcard.c smartcard.h \
spdb.c spdb.h \
state.c state.h \
timer.c timer.h \
vendor.c vendor.h \
virtual.c virtual.h \
whack_attribute.c whack_attribute.h \
xauth/xauth_manager.c xauth/xauth_manager.h \
xauth/xauth_provider.h xauth/xauth_verifier.h \
x509.c x509.h \
builder.c builder.h \
rsaref/pkcs11t.h rsaref/pkcs11.h rsaref/unix.h rsaref/pkcs11f.h

LOCAL_SRC_FILES += $(call add_plugin, xauth)

# build pluto ------------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	$(strongswan_PATH)/src/libhydra \
	$(strongswan_PATH)/src/libstrongswan \
	$(strongswan_PATH)/src/libfreeswan \
	$(strongswan_PATH)/src/whack

LOCAL_CFLAGS := $(strongswan_CFLAGS) \
	-DPLUTO -DVENDORID -DXAUTH_VID -DCISCO_QUIRKS \
	-DTHREADS -DKERNEL26_HAS_KAME_DUPLICATES \
	-DPLUGINS='"$(strongswan_PLUTO_PLUGINS)"'

LOCAL_MODULE := pluto

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libstrongswan libhydra libfreeswan libcutils

include $(BUILD_EXECUTABLE)
