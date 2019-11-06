AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

# these files are also used by the tests, we can't directly refer to them
# because of the subdirectory, which would cause distclean to fail
noinst_LTLIBRARIES = libfrodo.la
libfrodo_la_SOURCES = \
	frodo.h frodo.c \
	frodo_params.h frodo_params.c \
	frodo_utils.h frodo_utils.c

if MONOLITHIC
noinst_LTLIBRARIES += libstrongswan-frodo.la
else
plugin_LTLIBRARIES = libstrongswan-frodo.la
endif

libstrongswan_frodo_la_SOURCES = \
	frodo_plugin.h frodo_plugin.c

libstrongswan_frodo_la_LDFLAGS = -module -avoid-version

libstrongswan_frodo_la_LIBADD = libfrodo.la
