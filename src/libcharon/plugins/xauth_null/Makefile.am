
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-xauth-null.la
else
plugin_LTLIBRARIES = libstrongswan-xauth-null.la
endif

libstrongswan_xauth_null_la_SOURCES = \
	xauth_null_plugin.h xauth_null_plugin.c xauth_null.h xauth_null.c

libstrongswan_xauth_null_la_LDFLAGS = -module -avoid-version
