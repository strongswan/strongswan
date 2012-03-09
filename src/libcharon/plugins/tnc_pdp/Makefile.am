
INCLUDES = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libradius

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnc-pdp.la
else
plugin_LTLIBRARIES = libstrongswan-tnc-pdp.la
libstrongswan_tnc_pdp_la_LIBADD = \
	$(top_builddir)/src/libradius/libradius.la \
	$(top_builddir)/src/libtls/libtls.la \
	$(top_builddir)/src/libtnccs/libtnccs.la
endif

libstrongswan_tnc_pdp_la_SOURCES = \
	tnc_pdp_plugin.h tnc_pdp_plugin.c \
	tnc_pdp.h tnc_pdp.c tnc_pdp_connections.h tnc_pdp_connections.c 

libstrongswan_tnc_pdp_la_LDFLAGS = -module -avoid-version
