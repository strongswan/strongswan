AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-quota.la
else
plugin_LTLIBRARIES = libstrongswan-quota.la
endif

libstrongswan_quota_la_SOURCES = \
	quota_plugin.h quota_plugin.c \
	quota_accounting.h quota_accounting.c \
	quota_invoke.h quota_invoke.c


libstrongswan_quota_la_LDFLAGS = -module -avoid-version
