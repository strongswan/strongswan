
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic \
	-DIPSEC_PIDDIR=\"${piddir}\"

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-certexpire.la
else
plugin_LTLIBRARIES = libstrongswan-certexpire.la
endif

libstrongswan_certexpire_la_SOURCES = certexpire_plugin.h certexpire_plugin.c \
	certexpire_listener.h certexpire_listener.c \
	certexpire_export.h certexpire_export.c \
	certexpire_cron.h certexpire_cron.c

libstrongswan_certexpire_la_LDFLAGS = -module -avoid-version
