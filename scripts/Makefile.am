INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
-DIPSEC_PLUGINDIR=\"${plugindir}\" \
-DSTRONGSWAN_CONF=\"${strongswan_conf}\"

noinst_PROGRAMS = bin2array bin2sql id2sql key2keyid keyid2sql \
	thread_analysis dh_speed pubkey_speed
bin2array_SOURCES = bin2array.c
bin2sql_SOURCES = bin2sql.c
id2sql_SOURCES = id2sql.c
key2keyid_SOURCES = key2keyid.c
keyid2sql_SOURCES = keyid2sql.c
thread_analysis_SOURCES = thread_analysis.c
dh_speed_SOURCES = dh_speed.c
pubkey_speed_SOURCES = pubkey_speed.c
id2sql_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
key2keyid_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
keyid2sql_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
dh_speed_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lrt
pubkey_speed_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lrt
