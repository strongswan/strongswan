
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-android.la

libstrongswan_android_la_SOURCES = \
  android_plugin.c android_plugin.h \
  android_handler.c android_handler.h

libstrongswan_android_la_LDFLAGS = -module -avoid-version
libstrongswan_android_la_LIBADD = -lcutils
