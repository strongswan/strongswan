
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv

AM_CFLAGS = -rdynamic

imcv_LTLIBRARIES = imv-os.la

imv_os_la_LIBADD = $(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

imv_os_la_SOURCES = imv_os.c imv_os_state.h imv_os_state.c

imv_os_la_LDFLAGS = -module -avoid-version

