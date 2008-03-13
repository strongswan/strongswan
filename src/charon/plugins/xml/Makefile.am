
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon ${xml_CFLAGS}

AM_CFLAGS = -rdynamic -DIPSEC_PIDDIR=\"${piddir}\"

plugin_LTLIBRARIES = libcharon-xml.la
libcharon_xml_la_SOURCES = xml.h xml.c
libcharon_xml_la_LDFLAGS = -module
libcharon_xml_la_LIBADD = ${xml_LIBS}

