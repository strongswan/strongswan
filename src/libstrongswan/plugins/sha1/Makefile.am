
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-sha1.la
else
plugin_LTLIBRARIES = libstrongswan-sha1.la
libstrongswan_sha1_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_sha1_la_SOURCES = sha1_plugin.h sha1_plugin.c \
	sha1_hasher.c sha1_hasher.h sha1_prf.c sha1_prf.h
libstrongswan_sha1_la_LDFLAGS = -module -avoid-version
