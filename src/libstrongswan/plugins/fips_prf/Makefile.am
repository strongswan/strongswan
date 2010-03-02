
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-fips-prf.la
else
plugin_LTLIBRARIES = libstrongswan-fips-prf.la
libstrongswan_fips_prf_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_fips_prf_la_SOURCES = \
	fips_prf_plugin.h fips_prf_plugin.c fips_prf.c fips_prf.h

libstrongswan_fips_prf_la_LDFLAGS = -module -avoid-version
