
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-simaka-reauth.la
else
plugin_LTLIBRARIES = libstrongswan-eap-simaka-reauth.la
endif

libstrongswan_eap_simaka_reauth_la_SOURCES = \
	eap_simaka_reauth_plugin.h eap_simaka_reauth_plugin.c \
	eap_simaka_reauth_card.h eap_simaka_reauth_card.c \
	eap_simaka_reauth_provider.h eap_simaka_reauth_provider.c

libstrongswan_eap_simaka_reauth_la_LDFLAGS = -module -avoid-version
