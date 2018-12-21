AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-syscfg.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-syscfg.la
endif

libstrongswan_kernel_syscfg_la_SOURCES = \
	kernel_syscfg_plugin.h kernel_syscfg_plugin.c \
	kernel_syscfg_net.h kernel_syscfg_net.c

libstrongswan_kernel_syscfg_la_LDFLAGS = -module -avoid-version \
-framework SystemConfiguration -framework CoreFoundation
