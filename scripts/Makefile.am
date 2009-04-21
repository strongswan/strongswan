INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
-DIPSEC_PLUGINDIR=\"${plugindir}\" \
-Wformat=0

noinst_PROGRAMS = bin2array bin2sql id2sql key2keyid keyid2sql thread_analysis
bin2array_SOURCES = bin2array.c
bin2sql_SOURCES = bin2sql.c
id2sql_SOURCES = id2sql.c
key2keyid_SOURCES = key2keyid.c
keyid2sql_SOURCES = keyid2sql.c
thread_analysis_SOURCES = thread_analysis.c
id2sql_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
key2keyid_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
keyid2sql_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
