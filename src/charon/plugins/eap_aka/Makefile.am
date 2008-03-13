
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libcharon-eapaka.la

libcharon_eapaka_la_SOURCES = eap_aka_plugin.h eap_aka_plugin.c eap_aka.h eap_aka.c
libcharon_eapaka_la_LDFLAGS = -module
libcharon_eapaka_la_LIBADD = -lgmp

