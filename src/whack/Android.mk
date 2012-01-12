LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
LOCAL_SRC_FILES := \
whack.c whack.h

# build whack ------------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	$(strongswan_PATH)/src/libstrongswan \
	$(strongswan_PATH)/src/libfreeswan \
	$(strongswan_PATH)/src/libhydra \
	$(strongswan_PATH)/src/pluto

LOCAL_CFLAGS := $(strongswan_CFLAGS)

LOCAL_MODULE := whack

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libstrongswan libfreeswan

include $(BUILD_EXECUTABLE)

