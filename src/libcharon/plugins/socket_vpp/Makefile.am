AM_CPPFLAGS = \
    -I${linux_headers} \
    -I$(top_srcdir)/src/libstrongswan \
    -I$(top_srcdir)/src/libcharon/plugins/kernel_vpp \
    -I$(top_srcdir)/src/libcharon \
    -I$(top_srcdir)/src/libipsec

AM_CFLAGS = \
    $(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-socket-vpp.la
else
plugin_LTLIBRARIES = libstrongswan-socket-vpp.la
endif

libstrongswan_socket_vpp_la_SOURCES = \
    socket_vpp_plugin.h socket_vpp_plugin.c \
    socket_vpp_socket.h socket_vpp_socket.c

libstrongswan_socket_vpp_la_LIBADD = $(top_builddir)/src/libipsec/libipsec.la -lvlibmemoryclient -lsvm -lvppinfra -lvlib

libstrongswan_socket_vpp_la_LDFLAGS = -module -avoid-version
