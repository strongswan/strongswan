
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-socket-raw.la
else
plugin_LTLIBRARIES = libstrongswan-socket-raw.la
endif

libstrongswan_socket_raw_la_SOURCES = \
	socket_raw_plugin.h socket_raw_plugin.c \
	socket_raw_socket.h socket_raw_socket.c

libstrongswan_socket_raw_la_LDFLAGS = -module -avoid-version
