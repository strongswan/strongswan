LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
libhydra_la_SOURCES := \
hydra.c hydra.h

LOCAL_SRC_FILES := $(filter %.c,$(libhydra_la_SOURCES))

# adding the plugin source files

# build libhydra ---------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(strongswan_PATH)/src/libstrongswan

LOCAL_CFLAGS := $(strongswan_CFLAGS)

LOCAL_MODULE := libhydra

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libstrongswan

include $(BUILD_SHARED_LIBRARY)
