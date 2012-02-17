LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := libvstr.a

LOCAL_MODULE := libvstr

LOCAL_PRELINK_MODULE := false

include $(PREBUILT_STATIC_LIBRARY)
