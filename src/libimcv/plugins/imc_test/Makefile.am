
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-imc-test.la

libstrongswan_imc_test_la_LIBADD = $(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

libstrongswan_imc_test_la_SOURCES = imc_test.c \
	imc_test_state.h imc_test_state.c

libstrongswan_imc_test_la_LDFLAGS = -module -avoid-version

