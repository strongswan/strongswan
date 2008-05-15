
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-eapmd5.la

libstrongswan_eapmd5_la_SOURCES = eap_md5_plugin.h eap_md5_plugin.c eap_md5.h eap_md5.c
libstrongswan_eapmd5_la_LDFLAGS = -module

