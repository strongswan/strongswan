
INCLUDES = -I${linuxdir} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-kernel-netlink.la

libstrongswan_kernel_netlink_la_SOURCES = kernel_netlink_plugin.h kernel_netlink_plugin.c \
	kernel_netlink_ipsec.h kernel_netlink_ipsec.c kernel_netlink_net.h kernel_netlink_net.c \
	kernel_netlink_shared.h kernel_netlink_shared.c
libstrongswan_kernel_netlink_la_LDFLAGS = -module -avoid-version
