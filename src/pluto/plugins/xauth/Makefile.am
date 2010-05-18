
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
		   -I$(top_srcdir)/src/libfreeswan -I$(top_srcdir)/src/whack \
		   -I$(top_srcdir)/src/pluto

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-xauth.la

libstrongswan_xauth_la_SOURCES = \
	xauth_plugin.h xauth_plugin.c \
	xauth_default_provider.c xauth_default_provider.h \
	xauth_default_verifier.c xauth_default_verifier.h

libstrongswan_xauth_la_LDFLAGS = -module -avoid-version
