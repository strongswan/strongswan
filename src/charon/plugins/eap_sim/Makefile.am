
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic -DIPSEC_CONFDIR=\"${confdir}\" -DSIM_READER_LIB=\"${simreader}\"

plugin_LTLIBRARIES = libstrongswan-eapsim.la

libstrongswan_eapsim_la_SOURCES = eap_sim.h eap_sim.c \
  eap_sim_plugin.h eap_sim_plugin.c
libstrongswan_eapsim_la_LDFLAGS = -module

