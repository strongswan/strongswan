
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-socket-dynamic.la

libstrongswan_socket_dynamic_la_SOURCES = \
	socket_dynamic_plugin.h socket_dynamic_plugin.c \
	socket_dynamic_socket.h socket_dynamic_socket.c
libstrongswan_socket_dynamic_la_LDFLAGS = -module -avoid-version
