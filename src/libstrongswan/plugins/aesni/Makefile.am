AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-aesni.la
else
plugin_LTLIBRARIES = libstrongswan-aesni.la
endif

libstrongswan_aesni_la_SOURCES = \
	aesni_plugin.h aesni_plugin.c

libstrongswan_aesni_la_LDFLAGS = -module -avoid-version
