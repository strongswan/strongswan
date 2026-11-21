AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-cfg-subnet.la
else
plugin_LTLIBRARIES = libstrongswan-cfg-subnet.la
endif

libstrongswan_cfg_subnet_la_SOURCES = \
	cfg_subnet_plugin.h cfg_subnet_plugin.c \
	cfg_subnet_handler.h cfg_subnet_handler.c \
	cfg_subnet_narrow.h cfg_subnet_narrow.c

libstrongswan_cfg_subnet_la_LDFLAGS = -module -avoid-version
