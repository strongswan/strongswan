
INCLUDES = -I$(top_srcdir)/src/libstrongswan ${soup_CFLAGS}

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-soup.la
else
plugin_LTLIBRARIES = libstrongswan-soup.la
endif

libstrongswan_soup_la_SOURCES = \
	soup_plugin.h soup_plugin.c soup_fetcher.c soup_fetcher.h

libstrongswan_soup_la_LDFLAGS = -module -avoid-version
libstrongswan_soup_la_LIBADD  = ${soup_LIBS}
