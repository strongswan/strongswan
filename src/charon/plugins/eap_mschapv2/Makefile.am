
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-eap-mschapv2.la

libstrongswan_eap_mschapv2_la_SOURCES = \
	eap_mschapv2_plugin.h eap_mschapv2_plugin.c \
	eap_mschapv2.h eap_mschapv2.c
libstrongswan_eap_mschapv2_la_LDFLAGS = -module -avoid-version
libstrongswan_eap_mschapv2_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

