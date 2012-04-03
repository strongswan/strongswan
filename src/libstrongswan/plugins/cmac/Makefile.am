
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-cmac.la
else
plugin_LTLIBRARIES = libstrongswan-cmac.la
endif

libstrongswan_cmac_la_SOURCES = \
	cmac_plugin.h cmac_plugin.c cmac.h cmac.c \
	cmac_prf.h cmac_prf.c cmac_signer.h cmac_signer.c

libstrongswan_cmac_la_LDFLAGS = -module -avoid-version
