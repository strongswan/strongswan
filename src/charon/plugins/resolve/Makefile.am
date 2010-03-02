
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic \
  -DRESOLV_CONF=\"${resolv_conf}\"

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-resolve.la
else
plugin_LTLIBRARIES = libstrongswan-resolve.la
libstrongswan_resolve_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_resolve_la_SOURCES = \
	resolve_plugin.h resolve_plugin.c \
	resolve_handler.h resolve_handler.c

libstrongswan_resolve_la_LDFLAGS = -module -avoid-version
