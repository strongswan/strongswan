AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv \
	-I$(top_srcdir)/src/libpts

AM_CFLAGS = \
	-rdynamic

imcv_LTLIBRARIES = imv-swid.la

imv_swid_la_LIBADD = \
	$(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libpts/libpts.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

imv_swid_la_SOURCES = \
	imv_swid.c imv_swid_state.h imv_swid_state.c \
	imv_swid_agent.h imv_swid_agent.c

imv_swid_la_LDFLAGS = -module -avoid-version -no-undefined
