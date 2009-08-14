
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-pkcs1.la

libstrongswan_pkcs1_la_SOURCES = pkcs1_plugin.h pkcs1_plugin.c \
  pkcs1_builder.h pkcs1_builder.c

libstrongswan_pkcs1_la_LDFLAGS = -module -avoid-version

