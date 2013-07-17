AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra

AM_CFLAGS = \
	-rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-klips.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-klips.la
endif

libstrongswan_kernel_klips_la_SOURCES = \
	kernel_klips_plugin.h kernel_klips_plugin.c \
	kernel_klips_ipsec.h kernel_klips_ipsec.c pfkeyv2.h

libstrongswan_kernel_klips_la_LDFLAGS = -module -avoid-version
