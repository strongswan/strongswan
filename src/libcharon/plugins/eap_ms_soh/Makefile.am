
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-ms-soh.la
else
plugin_LTLIBRARIES = libstrongswan-eap-ms-soh.la
endif

libstrongswan_eap_ms_soh_la_SOURCES = \
	eap_ms_soh_plugin.h eap_ms_soh_plugin.c eap_ms_soh.h eap_ms_soh.c

libstrongswan_eap_ms_soh_la_LDFLAGS = -module -avoid-version
