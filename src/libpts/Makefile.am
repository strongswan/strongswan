
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libimcv

ipseclib_LTLIBRARIES = libpts.la

libpts_la_LIBADD = -ltspi

libpts_la_SOURCES = \
	pts/pts.h pts/pts.c \
	pts/pts_error.h pts/pts_error.c \
	pts/pts_proto_caps.h pts/pts_funct_comp_name.h \
	pts/pts_creds.h pts/pts_creds.c \
	pts/pts_database.h pts/pts_database.c \
	pts/pts_file_meas.h pts/pts_file_meas.c \
	pts/pts_meas_algo.h pts/pts_meas_algo.c \
	tcg/tcg_attr.h tcg/tcg_attr.c \
	tcg/tcg_pts_attr_proto_caps.h tcg/tcg_pts_attr_proto_caps.c \
	tcg/tcg_pts_attr_meas_algo.h tcg/tcg_pts_attr_meas_algo.c \
	tcg/tcg_pts_attr_get_tpm_version_info.h tcg/tcg_pts_attr_get_tpm_version_info.c \
	tcg/tcg_pts_attr_tpm_version_info.h tcg/tcg_pts_attr_tpm_version_info.c \
	tcg/tcg_pts_attr_get_aik.h tcg/tcg_pts_attr_get_aik.c \
	tcg/tcg_pts_attr_aik.h tcg/tcg_pts_attr_aik.c \
	tcg/tcg_pts_attr_req_funct_comp_evid.h tcg/tcg_pts_attr_req_funct_comp_evid.c \
	tcg/tcg_pts_attr_gen_attest_evid.h tcg/tcg_pts_attr_gen_attest_evid.c \
	tcg/tcg_pts_attr_simple_comp_evid.h tcg/tcg_pts_attr_simple_comp_evid.c \
	tcg/tcg_pts_attr_simple_evid_final.h tcg/tcg_pts_attr_simple_evid_final.c \
	tcg/tcg_pts_attr_req_file_meas.h tcg/tcg_pts_attr_req_file_meas.c \
	tcg/tcg_pts_attr_file_meas.h tcg/tcg_pts_attr_file_meas.c
