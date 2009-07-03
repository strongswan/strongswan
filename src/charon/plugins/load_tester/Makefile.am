
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-load-tester.la

libstrongswan_load_tester_la_SOURCES = \
  load_tester_plugin.c load_tester_plugin.h \
  load_tester_config.c load_tester_config.h \
  load_tester_creds.c load_tester_creds.h \
  load_tester_ipsec.c load_tester_ipsec.h \
  load_tester_listener.c load_tester_listener.h \
  load_tester_diffie_hellman.c load_tester_diffie_hellman.h

libstrongswan_load_tester_la_LDFLAGS = -module -avoid-version

