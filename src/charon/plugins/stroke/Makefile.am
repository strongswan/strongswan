
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon -I$(top_srcdir)/src/stroke

AM_CFLAGS = -rdynamic -DIPSEC_CONFDIR=\"${confdir}\" -DIPSEC_PIDDIR=\"${piddir}\"

plugin_LTLIBRARIES = libcharon-stroke.la

libcharon_stroke_la_SOURCES = stroke.h stroke.c
libcharon_stroke_la_LDFLAGS = -module

