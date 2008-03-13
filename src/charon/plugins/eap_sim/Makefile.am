
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic -DIPSEC_CONFDIR=\"${confdir}\" -DSIM_READER_LIB=\"${simreader}\"

plugin_LTLIBRARIES = libcharon-eapsim.la libeapsim-file.la

libcharon_eapsim_la_SOURCES = eap_sim_plugin.h eap_sim_plugin.c eap_sim.h eap_sim.c
libcharon_eapsim_la_LDFLAGS = -module

libeapsim_file_la_SOURCES = eap_sim_file.c
libeapsim_file_la_LDFLAGS = -module

