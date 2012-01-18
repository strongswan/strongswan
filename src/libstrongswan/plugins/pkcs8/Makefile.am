
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pkcs8.la
else
plugin_LTLIBRARIES = libstrongswan-pkcs8.la
endif

libstrongswan_pkcs8_la_SOURCES = \
	pkcs8_plugin.h pkcs8_plugin.c

libstrongswan_pkcs8_la_LDFLAGS = -module -avoid-version
