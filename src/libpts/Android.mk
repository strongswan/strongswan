LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
libpts_la_SOURCES := \
	libpts.h libpts.c \
	pts/pts.h pts/pts.c \
	pts/pts_error.h pts/pts_error.c \
	pts/pts_pcr.h pts/pts_pcr.c \
	pts/pts_proto_caps.h \
	pts/pts_req_func_comp_evid.h \
	pts/pts_simple_evid_final.h \
	pts/pts_creds.h pts/pts_creds.c \
	pts/pts_database.h pts/pts_database.c \
	pts/pts_dh_group.h pts/pts_dh_group.c \
	pts/pts_file_meas.h pts/pts_file_meas.c \
	pts/pts_file_meta.h pts/pts_file_meta.c \
	pts/pts_file_type.h pts/pts_file_type.c \
	pts/pts_ima_bios_list.h pts/pts_ima_bios_list.c \
	pts/pts_ima_event_list.h pts/pts_ima_event_list.c \
	pts/pts_meas_algo.h pts/pts_meas_algo.c \
	pts/components/pts_component.h \
	pts/components/pts_component_manager.h pts/components/pts_component_manager.c \
	pts/components/pts_comp_evidence.h pts/components/pts_comp_evidence.c \
	pts/components/pts_comp_func_name.h pts/components/pts_comp_func_name.c \
	pts/components/ita/ita_comp_func_name.h pts/components/ita/ita_comp_func_name.c \
	pts/components/ita/ita_comp_ima.h pts/components/ita/ita_comp_ima.c \
	pts/components/ita/ita_comp_tboot.h pts/components/ita/ita_comp_tboot.c \
	pts/components/ita/ita_comp_tgrub.h pts/components/ita/ita_comp_tgrub.c \
	pts/components/tcg/tcg_comp_func_name.h pts/components/tcg/tcg_comp_func_name.c \
	swid/swid_error.h swid/swid_error.c \
	swid/swid_inventory.h swid/swid_inventory.c \
	swid/swid_tag.h swid/swid_tag.c \
	swid/swid_tag_id.h swid/swid_tag_id.c \
	tcg/tcg_attr.h tcg/tcg_attr.c \
	tcg/pts/tcg_pts_attr_proto_caps.h tcg/pts/tcg_pts_attr_proto_caps.c \
	tcg/pts/tcg_pts_attr_dh_nonce_params_req.h tcg/pts/tcg_pts_attr_dh_nonce_params_req.c \
	tcg/pts/tcg_pts_attr_dh_nonce_params_resp.h tcg/pts/tcg_pts_attr_dh_nonce_params_resp.c \
	tcg/pts/tcg_pts_attr_dh_nonce_finish.h tcg/pts/tcg_pts_attr_dh_nonce_finish.c \
	tcg/pts/tcg_pts_attr_meas_algo.h tcg/pts/tcg_pts_attr_meas_algo.c \
	tcg/pts/tcg_pts_attr_get_tpm_version_info.h tcg/pts/tcg_pts_attr_get_tpm_version_info.c \
	tcg/pts/tcg_pts_attr_tpm_version_info.h tcg/pts/tcg_pts_attr_tpm_version_info.c \
	tcg/pts/tcg_pts_attr_get_aik.h tcg/pts/tcg_pts_attr_get_aik.c \
	tcg/pts/tcg_pts_attr_aik.h tcg/pts/tcg_pts_attr_aik.c \
	tcg/pts/tcg_pts_attr_req_func_comp_evid.h tcg/pts/tcg_pts_attr_req_func_comp_evid.c \
	tcg/pts/tcg_pts_attr_gen_attest_evid.h tcg/pts/tcg_pts_attr_gen_attest_evid.c \
	tcg/pts/tcg_pts_attr_simple_comp_evid.h tcg/pts/tcg_pts_attr_simple_comp_evid.c \
	tcg/pts/tcg_pts_attr_simple_evid_final.h tcg/pts/tcg_pts_attr_simple_evid_final.c \
	tcg/pts/tcg_pts_attr_req_file_meas.h tcg/pts/tcg_pts_attr_req_file_meas.c \
	tcg/pts/tcg_pts_attr_file_meas.h tcg/pts/tcg_pts_attr_file_meas.c \
	tcg/pts/tcg_pts_attr_req_file_meta.h tcg/pts/tcg_pts_attr_req_file_meta.c \
	tcg/pts/tcg_pts_attr_unix_file_meta.h tcg/pts/tcg_pts_attr_unix_file_meta.c \
	tcg/swid/tcg_swid_attr_req.h tcg/swid/tcg_swid_attr_req.c \
	tcg/swid/tcg_swid_attr_tag_id_inv.h tcg/swid/tcg_swid_attr_tag_id_inv.c \
	tcg/swid/tcg_swid_attr_tag_inv.h tcg/swid/tcg_swid_attr_tag_inv.c

LOCAL_SRC_FILES := $(filter %.c,$(libpts_la_SOURCES))

# build libpts -----------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(strongswan_PATH)/src/libtncif \
	$(strongswan_PATH)/src/libimcv \
	$(strongswan_PATH)/src/libstrongswan

LOCAL_CFLAGS := $(strongswan_CFLAGS)

LOCAL_MODULE := libpts

LOCAL_MODULE_TAGS := optional

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libstrongswan libimcv

include $(BUILD_SHARED_LIBRARY)
