
INCLUDES = -I${linux_headers} -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-af-alg.la
else
plugin_LTLIBRARIES = libstrongswan-af-alg.la
endif

libstrongswan_af_alg_la_SOURCES = \
	af_alg_plugin.h af_alg_plugin.c \
	af_alg_hasher.h af_alg_hasher.c \
	af_alg_signer.h af_alg_signer.c

libstrongswan_af_alg_la_LDFLAGS = -module -avoid-version
