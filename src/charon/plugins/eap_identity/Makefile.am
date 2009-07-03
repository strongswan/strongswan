
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-eapidentity.la
libstrongswan_eapidentity_la_SOURCES = \
  eap_identity_plugin.h eap_identity_plugin.c eap_identity.h eap_identity.c
libstrongswan_eapidentity_la_LDFLAGS = -module -avoid-version

