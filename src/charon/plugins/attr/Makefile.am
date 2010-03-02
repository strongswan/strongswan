
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-attr.la
else
plugin_LTLIBRARIES = libstrongswan-attr.la
libstrongswan_attr_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_attr_la_SOURCES = \
	attr_plugin.h attr_plugin.c \
	attr_provider.h attr_provider.c

libstrongswan_attr_la_LDFLAGS = -module -avoid-version
