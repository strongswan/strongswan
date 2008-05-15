
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon ${dbus_CFLAGS}

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-dbus.la

libstrongswan_dbus_la_SOURCES = dbus.h dbus.c
libstrongswan_dbus_la_LDFLAGS = -module
libstrongswan_dbus_la_LIBADD = ${dbus_LIBS}

