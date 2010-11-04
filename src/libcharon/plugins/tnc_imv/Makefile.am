
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnc-imv.la
else
plugin_LTLIBRARIES = libstrongswan-tnc-imv.la
endif

libstrongswan_tnc_imv_la_SOURCES = \
	tnc_imv_plugin.h tnc_imv_plugin.c tnc_imv.h tnc_imv.c

libstrongswan_tnc_imv_la_LDFLAGS = -module -avoid-version

