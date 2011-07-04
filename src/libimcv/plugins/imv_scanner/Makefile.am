
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-imv-scanner.la

libstrongswan_imv_scanner_la_LIBADD = $(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

libstrongswan_imv_scanner_la_SOURCES = imv_scanner.c \
	imv_scanner_state.h imv_scanner_state.c

libstrongswan_imv_scanner_la_LDFLAGS = -module -avoid-version

