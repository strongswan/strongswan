
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon ${dbus_CFLAGS}

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libcharon-dbus.la

libcharon_dbus_la_SOURCES = dbus.h dbus.c
libcharon_dbus_la_LDFLAGS = -module
libcharon_dbus_la_LIBADD = ${dbus_LIBS}

