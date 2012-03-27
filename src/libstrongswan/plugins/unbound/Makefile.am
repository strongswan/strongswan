
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-unbound.la
else
plugin_LTLIBRARIES = libstrongswan-unbound.la
endif

libstrongswan_unbound_la_SOURCES = \
	unbound_plugin.h unbound_plugin.c unbound_resolver.c unbound_resolver.h

libstrongswan_unbound_la_LDFLAGS = -module -avoid-version
libstrongswan_unbound_la_LIBADD  = -lunbound -lldns
