
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-des.la

libstrongswan_des_la_SOURCES = des_plugin.h des_plugin.c des_crypter.c des_crypter.h
libstrongswan_des_la_LDFLAGS = -module -avoid-version
libstrongswan_des_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

