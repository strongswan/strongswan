
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-duplicheck.la
else
plugin_LTLIBRARIES = libstrongswan-duplicheck.la
endif

libstrongswan_duplicheck_la_SOURCES = duplicheck_plugin.h duplicheck_plugin.c \
	duplicheck_listener.h duplicheck_listener.c

libstrongswan_duplicheck_la_LDFLAGS = -module -avoid-version
