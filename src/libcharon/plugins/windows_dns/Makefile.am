AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-windows-dns.la
else
plugin_LTLIBRARIES = libstrongswan-windows-dns.la
endif

libstrongswan_windows_dns_la_SOURCES = \
	windows_dns_plugin.c windows_dns_plugin.h \
	windows_dns_handler.c windows_dns_handler.h

libstrongswan_windows_dns_la_LDFLAGS = -module -avoid-version
libstrongswan_windows_dns_la_LIBADD  = -liphlpapi -lws2_32 -loleaut32 -lole32
