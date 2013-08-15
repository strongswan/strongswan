AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv \
	-I$(top_srcdir)/src/libpts

AM_CFLAGS = \
	-rdynamic

imcv_LTLIBRARIES = imc-swid.la

imc_swid_la_LIBADD = \
	$(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libpts/libpts.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

imc_swid_la_SOURCES = imc_swid.c imc_swid_state.h imc_swid_state.c

imc_swid_la_LDFLAGS = -module -avoid-version
