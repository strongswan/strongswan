
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra -I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-radius.la
else
plugin_LTLIBRARIES = libstrongswan-eap-radius.la
endif

libstrongswan_eap_radius_la_SOURCES = \
	eap_radius_plugin.h eap_radius_plugin.c \
	eap_radius.h eap_radius.c \
	radius_client.h radius_client.c \
	radius_message.h radius_message.c

libstrongswan_eap_radius_la_LDFLAGS = -module -avoid-version
