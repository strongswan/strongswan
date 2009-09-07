
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic \
  -DRESOLV_CONF=\"${resolv_conf}\"

plugin_LTLIBRARIES = libstrongswan-resolv-conf.la
libstrongswan_resolv_conf_la_SOURCES = \
  resolv_conf_plugin.h resolv_conf_plugin.c \
  resolv_conf_handler.h resolv_conf_handler.c
libstrongswan_resolv_conf_la_LDFLAGS = -module -avoid-version


