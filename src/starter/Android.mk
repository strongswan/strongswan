LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am (update for LEX/YACC)
LOCAL_SRC_FILES := \
parser.c lexer.c ipsec-parser.h netkey.c args.h netkey.h \
starterwhack.c starterwhack.h starterstroke.c invokepluto.c confread.c \
starterstroke.h interfaces.c invokepluto.h confread.h interfaces.h args.c \
keywords.c files.h keywords.h cmp.c starter.c cmp.h exec.c invokecharon.c \
exec.h invokecharon.h loglite.c klips.c klips.h

# build starter ----------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	$(strongswan_PATH)/src/libhydra \
	$(strongswan_PATH)/src/libfreeswan \
	$(strongswan_PATH)/src/libstrongswan \
	$(strongswan_PATH)/src/libfreeswan \
	$(strongswan_PATH)/src/pluto \
	$(strongswan_PATH)/src/whack \
	$(strongswan_PATH)/src/stroke

LOCAL_CFLAGS := $(strongswan_CFLAGS) -DSTART_CHARON \
	-DPLUGINS='"$(strongswan_STARTER_PLUGINS)"'

ifneq ($(strongswan_BUILD_PLUTO),)
LOCAL_CFLAGS += -DSTART_PLUTO
endif

LOCAL_MODULE := starter

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_REQUIRED_MODULES := stroke
ifneq ($(strongswan_BUILD_PLUTO),)
LOCAL_REQUIRED_MODULES += whack
endif

LOCAL_SHARED_LIBRARIES += libstrongswan libhydra libfreeswan

include $(BUILD_EXECUTABLE)

