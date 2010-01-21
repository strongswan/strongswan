
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-eap-tls.la

libstrongswan_eap_tls_la_SOURCES = eap_tls_plugin.h eap_tls_plugin.c \
	eap_tls.h eap_tls.c tls/tls.h tls/tls.c
libstrongswan_eap_tls_la_LDFLAGS = -module -avoid-version
