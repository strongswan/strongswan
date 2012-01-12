LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
LOCAL_SRC_FILES := \
tnc/tnc.h tnc/tnc.c \
tnc/imc/imc.h tnc/imc/imc_manager.h \
tnc/imv/imv.h tnc/imv/imv_manager.h \
tnc/imv/imv_recommendations.h tnc/imv/imv_recommendations.c \
tnc/tnccs/tnccs.h tnc/tnccs/tnccs.c \
tnc/tnccs/tnccs_manager.h tnc/tnccs/tnccs_manager.c

# build libtncif ---------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	$(strongswan_PATH)/src/libtncif \
	$(strongswan_PATH)/src/libstrongswan

LOCAL_CFLAGS := $(strongswan_CFLAGS)

LOCAL_MODULE := libtnccs

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libstrongswan

include $(BUILD_SHARED_LIBRARY)

