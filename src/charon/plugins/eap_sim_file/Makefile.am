
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic -DIPSEC_CONFDIR=\"${confdir}\"

plugin_LTLIBRARIES = libstrongswan-eapsim-file.la

libstrongswan_eapsim_file_la_SOURCES = \
  eap_sim_file_plugin.h eap_sim_file_plugin.c \
  eap_sim_file_card.h eap_sim_file_card.c \
  eap_sim_file_provider.h eap_sim_file_provider.c \
  eap_sim_file_triplets.h eap_sim_file_triplets.c
libstrongswan_eapsim_file_la_LDFLAGS = -module

