LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am (update for LEX/YACC)
starter_SOURCES := \
parser.c lexer.c ipsec-parser.h netkey.c args.h netkey.h \
starterstroke.c confread.c \
starterstroke.h confread.h args.c \
keywords.c files.h keywords.h cmp.c starter.c cmp.h invokecharon.c \
invokecharon.h klips.c klips.h

LOCAL_SRC_FILES := $(filter %.c,$(starter_SOURCES))

# build starter ----------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	$(strongswan_PATH)/src/libhydra \
	$(strongswan_PATH)/src/libstrongswan \
	$(strongswan_PATH)/src/stroke

LOCAL_CFLAGS := $(strongswan_CFLAGS) -DSTART_CHARON \
	-DPLUGINS='"$(strongswan_STARTER_PLUGINS)"'

LOCAL_MODULE := starter

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_REQUIRED_MODULES := stroke

LOCAL_SHARED_LIBRARIES += libstrongswan libhydra

include $(BUILD_EXECUTABLE)

