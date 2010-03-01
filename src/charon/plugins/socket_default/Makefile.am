
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-socket-default.la
else
plugin_LTLIBRARIES = libstrongswan-socket-default.la
libstrongswan_socket_default_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_socket_default_la_SOURCES = \
	socket_default_socket.h socket_default_socket.c \
	socket_default_plugin.h socket_default_plugin.c

libstrongswan_socket_default_la_LDFLAGS = -module -avoid-version
