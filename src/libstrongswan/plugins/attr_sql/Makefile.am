
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic \
  -DPLUGINS=\""${libstrongswan_plugins}\""

plugin_LTLIBRARIES = libstrongswan-attr-sql.la
libstrongswan_attr_sql_la_SOURCES = \
  attr_sql_plugin.h attr_sql_plugin.c \
  sql_attribute.h sql_attribute.c
libstrongswan_attr_sql_la_LDFLAGS = -module -avoid-version

ipsec_PROGRAMS = pool
pool_SOURCES = pool.c
pool_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
