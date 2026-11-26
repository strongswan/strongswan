AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-compsigs.la
else
plugin_LTLIBRARIES = libstrongswan-compsigs.la
endif

libstrongswan_compsigs_la_SOURCES = \
	compsigs_plugin.h compsigs_plugin.c \
	compsigs_private_key.h compsigs_private_key.c \
	compsigs_public_key.h compsigs_public_key.c \
	compsigs_params.h compsigs_params.c

libstrongswan_compsigs_la_LDFLAGS = -module -avoid-version
