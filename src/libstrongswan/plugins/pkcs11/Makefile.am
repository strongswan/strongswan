
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pkcs11.la
else
plugin_LTLIBRARIES = libstrongswan-pkcs11.la
endif

libstrongswan_pkcs11_la_SOURCES = \
	pkcs11_plugin.h pkcs11_plugin.c pkcs11.h \
	pkcs11_library.h pkcs11_library.c \
	pkcs11_manager.h pkcs11_manager.c

libstrongswan_pkcs11_la_LDFLAGS = -module -avoid-version
