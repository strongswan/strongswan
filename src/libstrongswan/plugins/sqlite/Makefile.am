
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-sqlite.la
libstrongswan_sqlite_la_LIBADD =
else
plugin_LTLIBRARIES = libstrongswan-sqlite.la
libstrongswan_sqlite_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_sqlite_la_SOURCES = \
	sqlite_plugin.h sqlite_plugin.c \
	sqlite_database.h sqlite_database.c

libstrongswan_sqlite_la_LDFLAGS = -module -avoid-version
libstrongswan_sqlite_la_LIBADD += -lsqlite3

