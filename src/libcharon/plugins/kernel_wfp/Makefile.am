AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-wfp.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-wfp.la
endif

libstrongswan_kernel_wfp_la_SOURCES = \
	kernel_wfp_plugin.h kernel_wfp_plugin.c \
	kernel_wfp_ipsec.h kernel_wfp_ipsec.c

libstrongswan_kernel_wfp_la_LDFLAGS = -module -avoid-version
libstrongswan_kernel_wfp_la_LIBADD = -lfwpuclnt
