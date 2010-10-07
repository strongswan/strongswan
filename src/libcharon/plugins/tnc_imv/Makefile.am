
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon `xml2-config --cflags`

AM_CFLAGS = -rdynamic

libstrongswan_tnc_imv_la_LIBADD = -ltnc

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnc-imv.la
else
plugin_LTLIBRARIES = libstrongswan-tnc-imv.la
endif

libstrongswan_tnc_imv_la_SOURCES = \
	tnc_imv_plugin.h tnc_imv_plugin.c

libstrongswan_tnc_imv_la_LDFLAGS = -module -avoid-version

