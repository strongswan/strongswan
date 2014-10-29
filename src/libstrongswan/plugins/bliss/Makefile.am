AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) \
	@COVERAGE_CFLAGS@

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-bliss.la
else
plugin_LTLIBRARIES = libstrongswan-bliss.la
endif

libstrongswan_bliss_la_SOURCES = \
	bliss_plugin.h bliss_plugin.c \
	bliss_param_set.h bliss_param_set.c \
	bliss_private_key.h bliss_private_key.c \
	bliss_public_key.h bliss_public_key.c \
	bliss_fft.h bliss_fft.c \
	bliss_fft_params.h bliss_fft_params.c

libstrongswan_bliss_la_LDFLAGS = -module -avoid-version
