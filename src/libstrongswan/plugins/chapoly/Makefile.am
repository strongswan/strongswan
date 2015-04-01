AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-chapoly.la
else
plugin_LTLIBRARIES = libstrongswan-chapoly.la
endif

libstrongswan_chapoly_la_SOURCES = \
	chapoly_plugin.h chapoly_plugin.c \
	chapoly_drv.h chapoly_drv.c \
	chapoly_aead.h chapoly_aead.c

libstrongswan_chapoly_la_LDFLAGS = -module -avoid-version
