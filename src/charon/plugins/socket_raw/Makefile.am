
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-socket-raw.la

libstrongswan_socket_raw_la_SOURCES = \
	socket_raw_plugin.h socket_raw_plugin.c \
	socket_raw_socket.h socket_raw_socket.c
libstrongswan_socket_raw_la_LDFLAGS = -module -avoid-version
libstrongswan_socket_raw_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
