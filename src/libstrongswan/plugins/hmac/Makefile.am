
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-hmac.la

libstrongswan_hmac_la_SOURCES = hmac_plugin.h hmac_plugin.c hmac.h hmac.c \
	hmac_prf.h hmac_prf.c hmac_signer.h hmac_signer.c
libstrongswan_hmac_la_LDFLAGS = -module -avoid-version
libstrongswan_hmac_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

