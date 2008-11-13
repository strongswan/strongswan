
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-ha-sync.la
libstrongswan_ha_sync_la_SOURCES = \
  ha_sync_plugin.h ha_sync_plugin.c \
  ha_sync_message.h ha_sync_message.c \
  ha_sync_socket.h ha_sync_socket.c \
  ha_sync_dispatcher.h ha_sync_dispatcher.c \
  ha_sync_ike.h ha_sync_ike.c \
  ha_sync_child.h ha_sync_child.c
libstrongswan_ha_sync_la_LDFLAGS = -module

