
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-pgp.la

libstrongswan_pgp_la_SOURCES = pgp_plugin.h pgp_plugin.c \
  pgp_builder.h pgp_builder.c

libstrongswan_pgp_la_LDFLAGS = -module -avoid-version

