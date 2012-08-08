LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
LOCAL_SRC_FILES := \
android_jni.c android_jni.h \
backend/android_attr.c backend/android_attr.h \
backend/android_creds.c backend/android_creds.h \
backend/android_service.c backend/android_service.h \
charonservice.c charonservice.h \
kernel/android_ipsec.c kernel/android_ipsec.h \
kernel/android_net.c kernel/android_net.h \
vpnservice_builder.c vpnservice_builder.h

# build libandroidbridge -------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	$(strongswan_PATH)/src/libipsec \
	$(strongswan_PATH)/src/libhydra \
	$(strongswan_PATH)/src/libcharon \
	$(strongswan_PATH)/src/libstrongswan

LOCAL_CFLAGS := $(strongswan_CFLAGS) \
	-DPLUGINS='"$(strongswan_CHARON_PLUGINS)"'

LOCAL_MODULE := libandroidbridge

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_LDLIBS := -llog

LOCAL_SHARED_LIBRARIES := libstrongswan libhydra libipsec libcharon

include $(BUILD_SHARED_LIBRARY)


