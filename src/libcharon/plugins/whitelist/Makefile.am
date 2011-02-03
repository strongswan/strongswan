
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic \
	-DIPSEC_PIDDIR=\"${piddir}\"

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-whitelist.la
else
plugin_LTLIBRARIES = libstrongswan-whitelist.la
endif

libstrongswan_whitelist_la_SOURCES = whitelist_plugin.h whitelist_plugin.c \
	whitelist_listener.h whitelist_listener.c whitelist_msg.h \
	whitelist_control.h whitelist_control.c

libstrongswan_whitelist_la_LDFLAGS = -module -avoid-version

ipsec_PROGRAMS = whitelist
whitelist_SOURCES = whitelist.c
