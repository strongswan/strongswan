ipseclib_LTLIBRARIES = libipsec.la

libipsec_la_SOURCES = \
ipsec.c ipsec.h \
esp_context.c esp_context.h \
esp_packet.c esp_packet.h \
ipsec_sa.c ipsec_sa.h

libipsec_la_LIBADD =

INCLUDES = \
	-I$(top_srcdir)/src/libstrongswan

EXTRA_DIST = Android.mk

# build optional plugins
########################

if MONOLITHIC
SUBDIRS =
else
SUBDIRS = .
endif

