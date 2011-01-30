
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon -I$(top_srcdir)/src/libtls

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnccs-dynamic.la
else
plugin_LTLIBRARIES = libstrongswan-tnccs-dynamic.la
libstrongswan_tnccs_dynamic_la_LIBADD = $(top_builddir)/src/libtls/libtls.la
endif

libstrongswan_tnccs_dynamic_la_SOURCES = \
	tnccs_dynamic_plugin.h tnccs_dynamic_plugin.c tnccs_dynamic.h tnccs_dynamic.c

libstrongswan_tnccs_dynamic_la_LDFLAGS = -module -avoid-version
