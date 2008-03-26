
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon -I$(top_srcdir)/src/stroke

AM_CFLAGS = -rdynamic -DIPSEC_CONFDIR=\"${confdir}\" -DIPSEC_PIDDIR=\"${piddir}\"

plugin_LTLIBRARIES = libcharon-stroke.la

libcharon_stroke_la_SOURCES = stroke_plugin.h stroke_plugin.c \
  stroke_socket.h stroke_socket.c \
  stroke_config.h stroke_config.c \
  stroke_control.h stroke_control.c \
  stroke_cred.h stroke_cred.c \
  stroke_ca.h stroke_ca.c \
  stroke_list.h stroke_list.c \
  stroke_shared_key.h stroke_shared_key.c

libcharon_stroke_la_LDFLAGS = -module

