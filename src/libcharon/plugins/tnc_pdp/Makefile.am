
INCLUDES = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnc-pdp.la
else
plugin_LTLIBRARIES = libstrongswan-tnc-pdp.la
libstrongswan_tnc_pdp_la_LIBADD = \
	$(top_builddir)/src/libtls/libtls.la \
	$(top_builddir)/src/libtnccs/libtnccs.la
endif

libstrongswan_tnc_pdp_la_SOURCES = \
	tnc_pdp_plugin.h tnc_pdp_plugin.c tnc_pdp.h tnc_pdp.c

libstrongswan_tnc_pdp_la_LDFLAGS = -module -avoid-version
