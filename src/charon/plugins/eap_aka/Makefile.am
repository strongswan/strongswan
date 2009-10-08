
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-eapaka.la

libstrongswan_eapaka_la_SOURCES = eap_aka_plugin.h eap_aka_plugin.c eap_aka.h eap_aka.c
libstrongswan_eapaka_la_LDFLAGS = -module -avoid-version

