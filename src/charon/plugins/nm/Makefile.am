
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon ${nm_CFLAGS}

AM_CFLAGS = -rdynamic -Wformat=0

plugin_LTLIBRARIES = libstrongswan-nm.la
libstrongswan_nm_la_SOURCES = \
  nm_plugin.h nm_plugin.c nm_service.h nm_service.c nm_creds.h nm_creds.c
libstrongswan_nm_la_LDFLAGS = -module
libstrongswan_nm_la_LIBADD = ${nm_LIBS}
