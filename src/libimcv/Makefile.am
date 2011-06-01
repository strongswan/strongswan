
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libcharon

noinst_LTLIBRARIES = libimcv.la

libimcv_la_SOURCES = \
	imc/imc_agent.h imc/imc_agent.c imc/imc_state.h \
	imv/imv_agent.h imv/imv_agent.c imv/imv_state.h \
	ietf/ietf_attr.h \
	ietf/ietf_attr_pa_tnc_error.h ietf/ietf_attr_pa_tnc_error.c \
	ita/ita_attr_command.h ita/ita_attr_command.c \
	pa_tnc/pa_tnc_msg.h pa_tnc/pa_tnc_msg.c \
	pa_tnc/pa_tnc_attr.h pa_tnc/pa_tnc_attr.c

SUBDIRS = .

if USE_IMC_TEST
  SUBDIRS += plugins/imc_test
endif

if USE_IMV_TEST
  SUBDIRS += plugins/imv_test
endif
