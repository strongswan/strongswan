
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif

ipseclib_LTLIBRARIES = libimcv.la

libimcv_la_LIBADD = $(top_builddir)/src/libtncif/libtncif.la

libimcv_la_SOURCES = \
	imcv.h imcv.c \
	imc/imc_agent.h imc/imc_agent.c imc/imc_state.h \
	imv/imv_agent.h imv/imv_agent.c imv/imv_state.h \
	ietf/ietf_attr.h ietf/ietf_attr.c \
	ietf/ietf_attr_assess_result.h ietf/ietf_attr_assess_result.c \
	ietf/ietf_attr_attr_request.h ietf/ietf_attr_attr_request.c \
	ietf/ietf_attr_fwd_enabled.h ietf/ietf_attr_fwd_enabled.c \
	ietf/ietf_attr_installed_packages.h ietf/ietf_attr_installed_packages.c \
	ietf/ietf_attr_pa_tnc_error.h ietf/ietf_attr_pa_tnc_error.c \
	ietf/ietf_attr_port_filter.h ietf/ietf_attr_port_filter.c \
	ietf/ietf_attr_product_info.h ietf/ietf_attr_product_info.c \
	ietf/ietf_attr_string_version.h ietf/ietf_attr_string_version.c \
	ita/ita_attr.h ita/ita_attr.c \
	ita/ita_attr_command.h ita/ita_attr_command.c \
	ita/ita_attr_dummy.h ita/ita_attr_dummy.c \
	os_info/os_info.h os_info/os_info.c \
	pa_tnc/pa_tnc_attr.h \
	pa_tnc/pa_tnc_msg.h pa_tnc/pa_tnc_msg.c \
	pa_tnc/pa_tnc_attr_manager.h pa_tnc/pa_tnc_attr_manager.c

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

if USE_IMC_OS
  SUBDIRS += plugins/imc_os
endif

if USE_IMV_OS
  SUBDIRS += plugins/imv_os
endif
