AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-cga.la
else
plugin_LTLIBRARIES = libstrongswan-cga.la
endif

libstrongswan_cga_la_SOURCES = \
	cga_cert.h cga_cert.c \
	cga_trust.h cga_trust.c \
	cga_plugin.h cga_plugin.c

libstrongswan_cga_la_LDFLAGS = -module -avoid-version
