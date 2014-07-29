AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-DIPSEC_PIDDIR=\"${piddir}\"

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-external-authorization.la
else
plugin_LTLIBRARIES = libstrongswan-external-authorization.la
endif

libstrongswan_external_authorization_la_SOURCES = external_authorization_plugin.h external_authorization_plugin.c \
	external_authorization_listener.h external_authorization_listener.c

libstrongswan_external_authorization_la_LDFLAGS = -module -avoid-version
