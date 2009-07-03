
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon ${xml_CFLAGS}

AM_CFLAGS = -rdynamic -DIPSEC_PIDDIR=\"${piddir}\"

plugin_LTLIBRARIES = libstrongswan-smp.la
libstrongswan_smp_la_SOURCES = smp.h smp.c
libstrongswan_smp_la_LDFLAGS = -module -avoid-version
libstrongswan_smp_la_LIBADD = ${xml_LIBS}

