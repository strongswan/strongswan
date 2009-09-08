
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic \
  -DSTRONGSWAN_CONF=\"${strongswan_conf}\" \
  -DPLUGINS=\""${libstrongswan_plugins}\""

plugin_LTLIBRARIES = libstrongswan-sql.la
libstrongswan_sql_la_SOURCES = sql_plugin.h sql_plugin.c \
  sql_config.h sql_config.c sql_cred.h sql_cred.c \
  sql_attribute.h sql_attribute.c sql_logger.h sql_logger.c
libstrongswan_sql_la_LDFLAGS = -module -avoid-version

ipsec_PROGRAMS = pool
pool_SOURCES = pool.c
pool_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
