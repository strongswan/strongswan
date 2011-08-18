
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif

ipseclib_LTLIBRARIES = libimcv.la

libimcv_la_LIBADD = $(top_builddir)/src/libtncif/libtncif.la

libimcv_la_SOURCES = \
	imcv.h imcv.c \
	imc/imc_agent.h imc/imc_agent.c imc/imc_state.h \
	imv/imv_agent.h imv/imv_agent.c imv/imv_state.h \
	ietf/ietf_attr.h ietf/ietf_attr.c \
	ietf/ietf_attr_pa_tnc_error.h ietf/ietf_attr_pa_tnc_error.c \
	ietf/ietf_attr_port_filter.h ietf/ietf_attr_port_filter.c \
	ita/ita_attr_command.h ita/ita_attr_command.c \
	pa_tnc/pa_tnc_msg.h pa_tnc/pa_tnc_msg.c \
	pa_tnc/pa_tnc_attr.h pa_tnc/pa_tnc_attr.c \
	tcg/tcg_attr.h tcg/tcg_attr.c \
	tcg/tcg_pts_attr_req_proto_caps.h tcg/tcg_pts_attr_req_proto_caps.c \
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

# CFLAGS = -Wall -Werror

SUBDIRS = .

if USE_IMC_TEST
  SUBDIRS += plugins/imc_test
endif

if USE_IMV_TEST
  SUBDIRS += plugins/imv_test
endif

if USE_IMC_SCANNER
  SUBDIRS += plugins/imc_scanner
endif

if USE_IMV_SCANNER
  SUBDIRS += plugins/imv_scanner
endif 

if USE_IMC_ATTESTATION
  SUBDIRS += plugins/imc_attestation
endif

if USE_IMV_ATTESTATION
  SUBDIRS += plugins/imv_attestation
endif
