
INCLUDES = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libtls \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	${xml_CFLAGS}

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnc-ifmap2.la
else
plugin_LTLIBRARIES = libstrongswan-tnc-ifmap2.la
endif

libstrongswan_tnc_ifmap2_la_LIBADD = \
	$(top_builddir)/src/libtls/libtls.la ${xml_LIBS}

libstrongswan_tnc_ifmap2_la_SOURCES = \
	tnc_ifmap2_plugin.h tnc_ifmap2_plugin.c \
	tnc_ifmap2_listener.h tnc_ifmap2_listener.c \
	tnc_ifmap2_soap.h tnc_ifmap2_soap.c

libstrongswan_tnc_ifmap2_la_LDFLAGS = -module -avoid-version

