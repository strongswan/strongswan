AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kdf.la
else
plugin_LTLIBRARIES = libstrongswan-kdf.la
endif

libstrongswan_kdf_la_SOURCES = \
	kdf_plugin.h kdf_plugin.c \
	kdf_prf_plus.h kdf_prf_plus.c

libstrongswan_kdf_la_LDFLAGS = -module -avoid-version
