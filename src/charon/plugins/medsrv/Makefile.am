
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-medsrv.la
else
plugin_LTLIBRARIES = libstrongswan-medsrv.la
libstrongswan_medsrv_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_medsrv_la_SOURCES = \
	medsrv_plugin.h medsrv_plugin.c \
	medsrv_creds.h medsrv_creds.c \
	medsrv_config.h medsrv_config.c

libstrongswan_medsrv_la_LDFLAGS = -module -avoid-version
