
INCLUDES = -I${linuxdir} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-kernel-pfroute.la

libstrongswan_kernel_pfroute_la_SOURCES = kernel_pfroute_plugin.h kernel_pfroute_plugin.c \
	kernel_pfroute_net.h kernel_pfroute_net.c
libstrongswan_kernel_pfroute_la_LDFLAGS = -module
