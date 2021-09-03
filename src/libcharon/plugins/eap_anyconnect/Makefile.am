AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	${xml_CFLAGS} \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-anyconnect.la
else
plugin_LTLIBRARIES = libstrongswan-eap-anyconnect.la
endif

libstrongswan_eap_anyconnect_la_SOURCES = \
	eap_anyconnect_plugin.h eap_anyconnect_plugin.c eap_anyconnect.h eap_anyconnect.c

libstrongswan_eap_anyconnect_la_LDFLAGS = -module -avoid-version
libstrongswan_eap_anyconnect_la_LIBADD  = ${xml_LIBS}
