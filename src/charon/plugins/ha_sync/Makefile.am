
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic -DIPSEC_PIDDIR=\"${piddir}\"

plugin_LTLIBRARIES = libstrongswan-ha-sync.la
libstrongswan_ha_sync_la_SOURCES = \
  ha_sync_plugin.h ha_sync_plugin.c \
  ha_sync_message.h ha_sync_message.c \
  ha_sync_socket.h ha_sync_socket.c \
  ha_sync_tunnel.h ha_sync_tunnel.c \
  ha_sync_dispatcher.h ha_sync_dispatcher.c \
  ha_sync_segments.h ha_sync_segments.c \
  ha_sync_kernel.h ha_sync_kernel.c \
  ha_sync_ctl.h ha_sync_ctl.c \
  ha_sync_ike.h ha_sync_ike.c \
  ha_sync_child.h ha_sync_child.c
libstrongswan_ha_sync_la_LDFLAGS = -module

