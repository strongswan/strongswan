AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-frodo.la
else
plugin_LTLIBRARIES = libstrongswan-frodo.la
endif

libstrongswan_frodo_la_SOURCES = \
	frodo_plugin.h frodo_plugin.c \
	frodo_kem.h frodo_kem.c \
	frodo_params.h frodo_params.c \
	frodo_utils.h frodo_utils.c

libstrongswan_frodo_la_LDFLAGS = -module -avoid-version
