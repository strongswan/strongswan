AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-DPLUGINS=\""${pool_plugins}\""

AM_CFLAGS = \
	-rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-attr-sql.la
else
plugin_LTLIBRARIES = libstrongswan-attr-sql.la
endif

libstrongswan_attr_sql_la_SOURCES = \
	attr_sql_plugin.h attr_sql_plugin.c \
	sql_attribute.h sql_attribute.c

libstrongswan_attr_sql_la_LDFLAGS = -module -avoid-version

ipsec_PROGRAMS = pool
pool_SOURCES = pool.c pool_attributes.c pool_attributes.h \
			   pool_usage.h pool_usage.c
pool_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la \
			 $(top_builddir)/src/libhydra/libhydra.la
pool.o :	$(top_builddir)/config.status
