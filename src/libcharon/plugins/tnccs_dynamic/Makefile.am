
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon -I$(top_srcdir)/src/libtls \
	-I$(top_srcdir)/src/libtncif

AM_CFLAGS = -DUSE_TNC -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnccs-dynamic.la
else
plugin_LTLIBRARIES = libstrongswan-tnccs-dynamic.la
endif

libstrongswan_tnccs_dynamic_la_SOURCES = \
	tnccs_dynamic_plugin.h tnccs_dynamic_plugin.c tnccs_dynamic.h tnccs_dynamic.c

libstrongswan_tnccs_dynamic_la_LDFLAGS = -module -avoid-version
