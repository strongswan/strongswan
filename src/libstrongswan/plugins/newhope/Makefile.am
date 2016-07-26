AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/math/libnttfft

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) \
	@COVERAGE_CFLAGS@

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-newhope.la
else
plugin_LTLIBRARIES = libstrongswan-newhope.la
endif

libstrongswan_newhope_la_SOURCES = \
	newhope_plugin.h newhope_plugin.c \
	newhope_ke.h newhope_ke.c \
	newhope_noise.h newhope_noise.c \
	newhope_reconciliation.h newhope_reconciliation.c

libstrongswan_newhope_la_LDFLAGS = -module -avoid-version

libstrongswan_newhope_la_LIBADD = \
	$(top_builddir)/src/libstrongswan/math/libnttfft/libnttfft.la

