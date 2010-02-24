
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-eap-gtc.la

libstrongswan_eap_gtc_la_SOURCES = eap_gtc_plugin.h eap_gtc_plugin.c eap_gtc.h eap_gtc.c
libstrongswan_eap_gtc_la_LDFLAGS = -module -avoid-version -lpam
libstrongswan_eap_gtc_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

