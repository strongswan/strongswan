LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
LOCAL_SRC_FILES := \
addrtoa.c addrtot.c addrtypeof.c anyaddr.c atoaddr.c atoasr.c \
atosubnet.c atoul.c copyright.c datatot.c freeswan.h \
goodmask.c initaddr.c initsaid.c initsubnet.c internal.h ipsec_param.h \
pfkey_v2_build.c pfkey_v2_debug.c \
pfkey_v2_ext_bits.c pfkey_v2_parse.c portof.c rangetoa.c \
pfkey.h pfkeyv2.h rangetosubnet.c sameaddr.c \
satot.c subnetof.c subnettoa.c subnettot.c \
subnettypeof.c ttoaddr.c ttodata.c ttoprotoport.c ttosa.c ttosubnet.c ttoul.c \
ultoa.c ultot.c

# build libfreeswan ------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	$(strongswan_PATH)/src/include \
	$(strongswan_PATH)/src/libstrongswan \
	$(strongswan_PATH)/src/libhydra \
	$(strongswan_PATH)/src/pluto

LOCAL_CFLAGS := $(strongswan_CFLAGS)

LOCAL_MODULE := libfreeswan

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libstrongswan

include $(BUILD_SHARED_LIBRARY)

