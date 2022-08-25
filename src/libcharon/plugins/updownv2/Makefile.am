AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-updownv2.la
else
plugin_LTLIBRARIES = libstrongswan-updownv2.la
endif

libstrongswan_updownv2_la_SOURCES = \
	updownv2_plugin.h updownv2_plugin.c \
	updownv2_handler.h updownv2_handler.c \
	updownv2_listener.h updownv2_listener.c

libstrongswan_updownv2_la_LDFLAGS = -module -avoid-version
