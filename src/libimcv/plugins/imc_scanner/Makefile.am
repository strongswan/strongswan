
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-imc-scanner.la

libstrongswan_imc_scanner_la_LIBADD = $(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

libstrongswan_imc_scanner_la_SOURCES = imc_scanner.c \
	imc_scanner_state.h imc_scanner_state.c

libstrongswan_imc_scanner_la_LDFLAGS = -module -avoid-version

