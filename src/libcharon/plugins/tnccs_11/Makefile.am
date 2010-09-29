
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon -I$(top_srcdir)/src/libtls \
	`xml2-config --cflags`

AM_CFLAGS = -rdynamic

libstrongswan_tnccs_11_la_LIBADD = -ltnc

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnccs-11.la
else
plugin_LTLIBRARIES = libstrongswan-tnccs-11.la
libstrongswan_tnccs_11_la_LIBADD += $(top_builddir)/src/libtls/libtls.la
endif

libstrongswan_tnccs_11_la_SOURCES = \
	tnccs_11_plugin.h tnccs_11_plugin.c tnccs_11.h tnccs_11.c

libstrongswan_tnccs_11_la_LDFLAGS = -module -avoid-version

