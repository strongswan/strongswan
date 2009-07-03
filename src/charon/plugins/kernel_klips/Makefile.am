
INCLUDES = -I${linuxdir} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-kernel-klips.la

libstrongswan_kernel_klips_la_SOURCES = kernel_klips_plugin.h kernel_klips_plugin.c \
	kernel_klips_ipsec.h kernel_klips_ipsec.c pfkeyv2.h
libstrongswan_kernel_klips_la_LDFLAGS = -module -avoid-version
