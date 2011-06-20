
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-imc-attestation.la

libstrongswan_imc_attestation_la_LIBADD = $(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

libstrongswan_imc_attestation_la_SOURCES = imc_attestation.c \
	imc_attestation_state.h imc_attestation_state.c

libstrongswan_imc_attestation_la_LDFLAGS = -module -avoid-version

