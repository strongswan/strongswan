
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libcharon-sql.la
libcharon_sql_la_SOURCES = sql_plugin.h sql_plugin.c \
  sql_config.h sql_config.c sql_cred.h sql_cred.c \
  sql_attribute.h sql_attribute.c sql_logger.h sql_logger.c
libcharon_sql_la_LDFLAGS = -module

