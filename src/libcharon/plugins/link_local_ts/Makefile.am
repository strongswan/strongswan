AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-link-local-ts.la
else
plugin_LTLIBRARIES = libstrongswan-link-local-ts.la
endif

libstrongswan_link_local_ts_la_SOURCES = \
	link_local_ts_plugin.h link_local_ts_plugin.c \
	link_local_ts_narrow.h link_local_ts_narrow.c

libstrongswan_link_local_ts_la_LDFLAGS = -module -avoid-version
