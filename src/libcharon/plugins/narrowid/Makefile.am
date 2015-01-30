AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-narrowid.la
else
plugin_LTLIBRARIES = libstrongswan-narrowid.la
endif

libstrongswan_narrowid_la_SOURCES = \
	narrowid_narrow.h narrowid_narrow.c \
	narrowid_plugin.h narrowid_plugin.c

libstrongswan_narrowid_la_LDFLAGS = -module -avoid-version
