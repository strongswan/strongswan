
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic \
  -DPLUGINS=\""${libstrongswan_plugins}\""

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-sql.la
else
plugin_LTLIBRARIES = libstrongswan-sql.la
libstrongswan_sql_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_sql_la_SOURCES = \
	sql_plugin.h sql_plugin.c sql_config.h sql_config.c \
	sql_cred.h sql_cred.c sql_logger.h sql_logger.c

libstrongswan_sql_la_LDFLAGS = -module -avoid-version
