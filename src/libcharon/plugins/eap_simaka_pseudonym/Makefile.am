
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-simaka-pseudonym.la
else
plugin_LTLIBRARIES = libstrongswan-eap-simaka-pseudonym.la
endif

libstrongswan_eap_simaka_pseudonym_la_SOURCES = \
	eap_simaka_pseudonym_plugin.h eap_simaka_pseudonym_plugin.c \
	eap_simaka_pseudonym_card.h eap_simaka_pseudonym_card.c \
	eap_simaka_pseudonym_provider.h eap_simaka_pseudonym_provider.c

libstrongswan_eap_simaka_pseudonym_la_LDFLAGS = -module -avoid-version
