
INCLUDES = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libtls \
	-I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libtnccs

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnccs-20.la
else
plugin_LTLIBRARIES = libstrongswan-tnccs-20.la
libstrongswan_tnccs_20_la_LIBADD = \
	$(top_builddir)/src/libtncif/libtncif.la \
	$(top_builddir)/src/libtnccs/libtnccs.la
endif

libstrongswan_tnccs_20_la_SOURCES = \
	tnccs_20_plugin.h tnccs_20_plugin.c tnccs_20.h tnccs_20.c \
	batch/pb_tnc_batch.h batch/pb_tnc_batch.c \
	messages/pb_tnc_msg.h messages/pb_tnc_msg.c \
	messages/pb_experimental_msg.h messages/pb_experimental_msg.c \
	messages/pb_pa_msg.h messages/pb_pa_msg.c \
	messages/pb_assessment_result_msg.h messages/pb_assessment_result_msg.c \
	messages/pb_access_recommendation_msg.h messages/pb_access_recommendation_msg.c \
	messages/pb_error_msg.h messages/pb_error_msg.c \
	messages/pb_language_preference_msg.h messages/pb_language_preference_msg.c \
	messages/pb_reason_string_msg.h messages/pb_reason_string_msg.c \
	messages/pb_remediation_parameters_msg.h messages/pb_remediation_parameters_msg.c \
	state_machine/pb_tnc_state_machine.h state_machine/pb_tnc_state_machine.c

libstrongswan_tnccs_20_la_LDFLAGS = -module -avoid-version
