AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

noinst_LTLIBRARIES =
if MONOLITHIC
noinst_LTLIBRARIES += libstrongswan-wintun.la
else
plugin_LTLIBRARIES = libstrongswan-wintun.la
endif

libstrongswan_wintun_la_SOURCES = \
	wintun_plugin.h wintun_plugin.c \
	wintun_device.h wintun_device.c

libstrongswan_wintun_la_LDFLAGS = -module -avoid-version

