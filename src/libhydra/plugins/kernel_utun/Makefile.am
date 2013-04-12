
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-utun.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-utun.la
endif

libstrongswan_kernel_utun_la_SOURCES = \
	kernel_utun_plugin.h kernel_utun_plugin.c \
	kernel_utun_ipsec.h kernel_utun_ipsec.c \
	kernel_utun_net.h kernel_utun_net.c

libstrongswan_kernel_utun_la_LDFLAGS = -module -avoid-version
