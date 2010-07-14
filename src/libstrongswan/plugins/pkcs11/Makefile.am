
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pkcs11.la
else
plugin_LTLIBRARIES = libstrongswan-pkcs11.la
endif

libstrongswan_pkcs11_la_SOURCES = \
	pkcs11_plugin.h pkcs11_plugin.c pkcs11.h

libstrongswan_pkcs11_la_LDFLAGS = -module -avoid-version
