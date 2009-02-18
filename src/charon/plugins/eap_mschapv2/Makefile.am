
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-eapmschapv2.la

libstrongswan_eapmschapv2_la_SOURCES = \
	eap_mschapv2_plugin.h eap_mschapv2_plugin.c \
	eap_mschapv2.h eap_mschapv2.c
libstrongswan_eapmschapv2_la_LDFLAGS = -module

