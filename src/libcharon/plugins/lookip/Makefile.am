
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-lookip.la
else
plugin_LTLIBRARIES = libstrongswan-lookip.la
endif

libstrongswan_lookip_la_SOURCES = lookip_plugin.h lookip_plugin.c \
	lookip_listener.h lookip_listener.c

libstrongswan_lookip_la_LDFLAGS = -module -avoid-version
