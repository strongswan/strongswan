
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon -I$(top_srcdir)/src/libimcv

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-imv-test.la

libstrongswan_imv_test_la_LIBADD = $(top_builddir)/src/libimcv/libimcv.la

libstrongswan_imv_test_la_SOURCES = imv_test.c \
	imv_test_state.h imv_test_state.c

libstrongswan_imv_test_la_LDFLAGS = -module -avoid-version

