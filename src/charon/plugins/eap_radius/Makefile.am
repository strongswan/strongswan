
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-radius.la
else
plugin_LTLIBRARIES = libstrongswan-eap-radius.la
libstrongswan_eap_radius_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_eap_radius_la_SOURCES = \
	eap_radius_plugin.h eap_radius_plugin.c \
	eap_radius.h eap_radius.c \
	radius_client.h radius_client.c \
	radius_message.h radius_message.c

libstrongswan_eap_radius_la_LDFLAGS = -module -avoid-version
