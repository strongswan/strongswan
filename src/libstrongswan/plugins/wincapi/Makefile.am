
AM_CPPFLAGS = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = $(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-wincapi.la
else
plugin_LTLIBRARIES = libstrongswan-wincapi.la
endif

libstrongswan_wincapi_la_SOURCES = \
	wincapi_plugin.h wincapi_plugin.c \
	wincapi_private_key.h wincapi_private_key.c

libstrongswan_wincapi_la_LDFLAGS = -module -avoid-version
libstrongswan_wincapi_la_LIBADD  = -lcrypt32 -lncrypt
