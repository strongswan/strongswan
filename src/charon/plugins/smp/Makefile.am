
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon ${xml_CFLAGS}

AM_CFLAGS = -rdynamic -DIPSEC_PIDDIR=\"${piddir}\"

plugin_LTLIBRARIES = libcharon-smp.la
libcharon_smp_la_SOURCES = smp.h smp.c
libcharon_smp_la_LDFLAGS = -module
libcharon_smp_la_LIBADD = ${xml_LIBS}

