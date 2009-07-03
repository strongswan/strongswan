
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-random.la

libstrongswan_random_la_SOURCES = random_plugin.h random_plugin.c \
  random_rng.c random_rng.h
libstrongswan_random_la_LDFLAGS = -module -avoid-version

