
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-imv-attestation.la

libstrongswan_imv_attestation_la_LIBADD = $(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

libstrongswan_imv_attestation_la_SOURCES = imv_attestation.c \
	imv_attestation_state.h imv_attestation_state.c

libstrongswan_imv_attestation_la_LDFLAGS = -module -avoid-version

