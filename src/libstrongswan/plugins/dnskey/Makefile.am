
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-dnskey.la

libstrongswan_dnskey_la_SOURCES = dnskey_plugin.h dnskey_plugin.c \
  dnskey_builder.h dnskey_builder.c

libstrongswan_dnskey_la_LDFLAGS = -module -avoid-version
libstrongswan_dnskey_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

