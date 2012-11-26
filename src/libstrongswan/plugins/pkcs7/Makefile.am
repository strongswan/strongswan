
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pkcs7.la
else
plugin_LTLIBRARIES = libstrongswan-pkcs7.la
endif

libstrongswan_pkcs7_la_SOURCES = \
	pkcs7_plugin.h pkcs7_plugin.c

libstrongswan_pkcs7_la_LDFLAGS = -module -avoid-version
