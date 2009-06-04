
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-gcrypt.la

libstrongswan_gcrypt_la_SOURCES = gcrypt_plugin.h gcrypt_plugin.c

libstrongswan_gcrypt_la_LDFLAGS = -module
libstrongswan_gcrypt_la_LIBADD  = -lgcrypt

