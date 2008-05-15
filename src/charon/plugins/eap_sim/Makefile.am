
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic -DIPSEC_CONFDIR=\"${confdir}\" -DSIM_READER_LIB=\"${simreader}\"

plugin_LTLIBRARIES = libstrongswan-eapsim.la libeapsim-file.la

libstrongswan_eapsim_la_SOURCES = eap_sim_plugin.h eap_sim_plugin.c eap_sim.h eap_sim.c
libstrongswan_eapsim_la_LDFLAGS = -module

libeapsim_file_la_SOURCES = eap_sim_file.c
libeapsim_file_la_LDFLAGS = -module

