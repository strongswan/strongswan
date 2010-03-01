
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic $(MYSQLCFLAG)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-mysql.la
libstrongswan_mysql_la_LIBADD =
else
plugin_LTLIBRARIES = libstrongswan-mysql.la
libstrongswan_mysql_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_mysql_la_SOURCES = mysql_plugin.h mysql_plugin.c  \
	mysql_database.h mysql_database.c
libstrongswan_mysql_la_LDFLAGS = -module -avoid-version
libstrongswan_mysql_la_LIBADD += $(MYSQLLIB)

