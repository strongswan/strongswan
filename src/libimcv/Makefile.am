AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libtncif

ipseclib_LTLIBRARIES = libimcv.la

libimcv_la_LDFLAGS = \
	-no-undefined

libimcv_la_LIBADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libtncif/libtncif.la

libimcv_la_SOURCES = \
	imcv.h imcv.c \
	imc/imc_agent.h imc/imc_agent.c imc/imc_state.h \
	imc/imc_msg.h imc/imc_msg.c \
	imv/imv_agent.h imv/imv_agent.c imv/imv_state.h \
	imv/imv_agent_if.h imv/imv_if.h \
	imv/imv_database.h imv/imv_database.c \
	imv/imv_msg.h imv/imv_msg.c \
	imv/imv_lang_string.h imv/imv_lang_string.c \
	imv/imv_reason_string.h imv/imv_reason_string.c \
	imv/imv_remediation_string.h imv/imv_remediation_string.c \
	imv/imv_session.h imv/imv_session.c \
	imv/imv_workitem.h imv/imv_workitem.c \
	ietf/ietf_attr.h ietf/ietf_attr.c \
	ietf/ietf_attr_assess_result.h ietf/ietf_attr_assess_result.c \
	ietf/ietf_attr_attr_request.h ietf/ietf_attr_attr_request.c \
	ietf/ietf_attr_fwd_enabled.h ietf/ietf_attr_fwd_enabled.c \
	ietf/ietf_attr_default_pwd_enabled.h ietf/ietf_attr_default_pwd_enabled.c \
	ietf/ietf_attr_installed_packages.h ietf/ietf_attr_installed_packages.c \
	ietf/ietf_attr_numeric_version.h ietf/ietf_attr_numeric_version.c \
	ietf/ietf_attr_op_status.h ietf/ietf_attr_op_status.c \
	ietf/ietf_attr_pa_tnc_error.h ietf/ietf_attr_pa_tnc_error.c \
	ietf/ietf_attr_port_filter.h ietf/ietf_attr_port_filter.c \
	ietf/ietf_attr_product_info.h ietf/ietf_attr_product_info.c \
	ietf/ietf_attr_remediation_instr.h ietf/ietf_attr_remediation_instr.c \
	ietf/ietf_attr_string_version.h ietf/ietf_attr_string_version.c \
	ita/ita_attr.h ita/ita_attr.c \
	ita/ita_attr_command.h ita/ita_attr_command.c \
	ita/ita_attr_dummy.h ita/ita_attr_dummy.c \
	ita/ita_attr_get_settings.h ita/ita_attr_get_settings.c \
	ita/ita_attr_settings.h ita/ita_attr_settings.c \
	ita/ita_attr_angel.h ita/ita_attr_angel.c \
	ita/ita_attr_device_id.h ita/ita_attr_device_id.c \
	os_info/os_info.h os_info/os_info.c \
	pa_tnc/pa_tnc_attr.h \
	pa_tnc/pa_tnc_msg.h pa_tnc/pa_tnc_msg.c \
	pa_tnc/pa_tnc_attr_manager.h pa_tnc/pa_tnc_attr_manager.c

ipsec_SCRIPTS = imv/_imv_policy
EXTRA_DIST = imv/_imv_policy

templatesdir = $(pkgdatadir)/templates/database/imv
dist_templates_DATA = imv/tables.sql imv/data.sql

ipsec_PROGRAMS = imv_policy_manager
imv_policy_manager_SOURCES = \
	imv/imv_policy_manager.c \
	imv/imv_policy_manager_usage.h imv/imv_policy_manager_usage.c
imv_policy_manager_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la
#imv/imv_policy_manager.o :	$(top_builddir)/config.status

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
