
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-xcbc.la

libstrongswan_xcbc_la_SOURCES = xcbc_plugin.h xcbc_plugin.c xcbc.h xcbc.c \
	xcbc_prf.h xcbc_prf.c xcbc_signer.h xcbc_signer.c
libstrongswan_xcbc_la_LDFLAGS = -module

