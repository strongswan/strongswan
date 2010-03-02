
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-updown.la
else
plugin_LTLIBRARIES = libstrongswan-updown.la
libstrongswan_updown_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_updown_la_SOURCES = \
	updown_plugin.h updown_plugin.c \
	updown_listener.h updown_listener.c

libstrongswan_updown_la_LDFLAGS = -module -avoid-version
