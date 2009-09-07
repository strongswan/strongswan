
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-kernel-pfkey.la

libstrongswan_kernel_pfkey_la_SOURCES = kernel_pfkey_plugin.h kernel_pfkey_plugin.c \
	kernel_pfkey_ipsec.h kernel_pfkey_ipsec.c
libstrongswan_kernel_pfkey_la_LDFLAGS = -module -avoid-version
