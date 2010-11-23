
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon -I$(top_srcdir)/src/libtls

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnccs-20.la
else
plugin_LTLIBRARIES = libstrongswan-tnccs-20.la
libstrongswan_tnccs_20_la_LIBADD = $(top_builddir)/src/libtls/libtls.la
endif

libstrongswan_tnccs_20_la_SOURCES = \
	tnccs_20_plugin.h tnccs_20_plugin.c tnccs_20.h tnccs_20.c \
	tnccs_20_types.h tnccs_20_types.c \
	messages/pb_tnc_message.h messages/pb_tnc_message.c \
	messages/pb_pa_message.h messages/pb_pa_message.c

libstrongswan_tnccs_20_la_LDFLAGS = -module -avoid-version

