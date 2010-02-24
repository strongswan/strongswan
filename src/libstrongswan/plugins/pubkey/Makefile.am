
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-pubkey.la

libstrongswan_pubkey_la_SOURCES = pubkey_plugin.h pubkey_plugin.c \
  pubkey_cert.h pubkey_cert.c

libstrongswan_pubkey_la_LDFLAGS = -module -avoid-version
libstrongswan_pubkey_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

