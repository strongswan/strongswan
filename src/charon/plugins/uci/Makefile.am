
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-uci.la
libstrongswan_uci_la_SOURCES = \
  uci_plugin.h uci_plugin.c uci_parser.h uci_parser.c \
  uci_config.h uci_config.c uci_creds.h uci_creds.c \
  uci_control.h uci_control.c
libstrongswan_uci_la_LDFLAGS = -module -avoid-version
libstrongswan_uci_la_LIBADD = -luci


