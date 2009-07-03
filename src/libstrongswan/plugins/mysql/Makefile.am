
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-mysql.la

libstrongswan_mysql_la_SOURCES = mysql_plugin.h mysql_plugin.c  \
	mysql_database.h mysql_database.c
libstrongswan_mysql_la_LDFLAGS = -module -avoid-version
libstrongswan_mysql_la_LIBADD = -lmysqlclient_r

