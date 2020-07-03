AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-proxyarp.la
else
plugin_LTLIBRARIES = libstrongswan-proxyarp.la
endif

libstrongswan_proxyarp_la_SOURCES = \
	proxyarp_plugin.h proxyarp_plugin.c \
	proxyarp_listener.h proxyarp_listener.c

libstrongswan_proxyarp_la_LDFLAGS = -module -avoid-version
