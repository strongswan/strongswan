
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-af-alg.la
else
plugin_LTLIBRARIES = libstrongswan-af-alg.la
endif

libstrongswan_af_alg_la_SOURCES = \
	af_alg_plugin.h af_alg_plugin.c

libstrongswan_af_alg_la_LDFLAGS = -module -avoid-version
