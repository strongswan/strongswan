
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libcharon-sql.la
libcharon_sql_la_SOURCES = sql_plugin.h sql_plugin.c \
  sql_config.h sql_config.c
libcharon_sql_la_LDFLAGS = -module

