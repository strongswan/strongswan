
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon ${xml_CFLAGS}

AM_CFLAGS = -rdynamic -DIPSEC_PIDDIR=\"${piddir}\"

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-smp.la
else
plugin_LTLIBRARIES = libstrongswan-smp.la
endif

libstrongswan_smp_la_SOURCES = \
	smp.h smp.c

libstrongswan_smp_la_LDFLAGS = -module -avoid-version
libstrongswan_smp_la_LIBADD  = ${xml_LIBS}
