
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pem.la
else
plugin_LTLIBRARIES = libstrongswan-pem.la
endif

libstrongswan_pem_la_SOURCES = \
	pem_plugin.h pem_plugin.c \
	pem_builder.c pem_builder.h

libstrongswan_pem_la_LDFLAGS = -module -avoid-version
