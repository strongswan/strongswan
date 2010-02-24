
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-pem.la

libstrongswan_pem_la_SOURCES = pem_plugin.h pem_plugin.c \
  pem_builder.c pem_builder.h

libstrongswan_pem_la_LDFLAGS = -module -avoid-version
libstrongswan_pem_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

