AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-demo.la
else
plugin_LTLIBRARIES = libstrongswan-demo.la
endif

libstrongswan_demo_la_SOURCES = \
	demo_plugin.h demo_plugin.c \
	demo_listener.h demo_listener.c 

libstrongswan_demo_la_LDFLAGS = -module -avoid-version
