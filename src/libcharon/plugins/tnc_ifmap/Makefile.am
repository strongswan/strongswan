
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon ${axis2c_CFLAGS}

AM_CFLAGS = -rdynamic

libstrongswan_tnc_ifmap_la_LIBADD = ${axis2c_LIBS} -laxutil -laxis2_engine -laxis2_http_sender

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnc-ifmap.la
else
plugin_LTLIBRARIES = libstrongswan-tnc-ifmap.la
endif

libstrongswan_tnc_ifmap_la_SOURCES = \
	tnc_ifmap_plugin.h tnc_ifmap_plugin.c \
	tnc_ifmap_listener.h tnc_ifmap_listener.c \
	tnc_ifmap_soap.h tnc_ifmap_soap.c

libstrongswan_tnc_ifmap_la_LDFLAGS = -module -avoid-version

