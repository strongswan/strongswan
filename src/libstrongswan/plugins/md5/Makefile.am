
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-md5.la

libstrongswan_md5_la_SOURCES = md5_plugin.h md5_plugin.c md5_hasher.c md5_hasher.h
libstrongswan_md5_la_LDFLAGS = -module -avoid-version

