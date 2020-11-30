AM_CPPFLAGS = \
    -I${linux_headers} \
    -I$(top_srcdir)/src/libstrongswan \
    -I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
    $(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-vpp.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-vpp.la
endif

libstrongswan_kernel_vpp_la_SOURCES = \
    kernel_vpp_plugin.h kernel_vpp_plugin.c \
    kernel_vpp_ipsec.h kernel_vpp_ipsec.c \
    kernel_vpp_net.h kernel_vpp_net.c \
    kernel_vpp_shared.h kernel_vpp_shared.c

libstrongswan_kernel_vpp_la_LDFLAGS = -module -avoid-version
libstrongswan_kernel_vpp_la_LIBADD = -lvlibmemoryclient -lsvm -lvppinfra -lvlib
