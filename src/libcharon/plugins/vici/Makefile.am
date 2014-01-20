AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-DIPSEC_PIDDIR=\"${piddir}\"

AM_CFLAGS = \
	-rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-vici.la
else
plugin_LTLIBRARIES = libstrongswan-vici.la
endif

libstrongswan_vici_la_SOURCES = \
	vici_plugin.h vici_plugin.c

libstrongswan_vici_la_LDFLAGS = -module -avoid-version
