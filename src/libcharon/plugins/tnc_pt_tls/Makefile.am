AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libtls \
	-I$(top_srcdir)/src/libpttls \
	-I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libtnccs

AM_CFLAGS = \
	-rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnc-pt-tls.la
else
plugin_LTLIBRARIES = libstrongswan-tnc-pt-tls.la
libstrongswan_tnc_pt_tls_la_LIBADD = \
	$(top_builddir)/src/libtls/libtls.la \
	$(top_builddir)/src/libpttls/libpttls.la \
	$(top_builddir)/src/libtnccs/libtnccs.la
endif

libstrongswan_tnc_pt_tls_la_SOURCES = \
	tnc_pt_tls_plugin.h tnc_pt_tls_plugin.c \
	tnc_pt_tls_connection.h tnc_pt_tls_connection.c

libstrongswan_tnc_pt_tls_la_LDFLAGS = -module -avoid-version
