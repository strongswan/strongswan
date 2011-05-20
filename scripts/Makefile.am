INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtls
AM_CFLAGS = \
-DPLUGINS="\"${scripts_plugins}\""

noinst_PROGRAMS = bin2array bin2sql id2sql key2keyid keyid2sql oid2der \
	thread_analysis dh_speed pubkey_speed crypt_burn fetch

if USE_TLS
  noinst_PROGRAMS += tls_test
  tls_test_SOURCES = tls_test.c
  tls_test_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la \
					$(top_builddir)/src/libtls/libtls.la
endif

bin2array_SOURCES = bin2array.c
bin2sql_SOURCES = bin2sql.c
id2sql_SOURCES = id2sql.c
key2keyid_SOURCES = key2keyid.c
keyid2sql_SOURCES = keyid2sql.c
oid2der_SOURCES = oid2der.c
thread_analysis_SOURCES = thread_analysis.c
dh_speed_SOURCES = dh_speed.c
pubkey_speed_SOURCES = pubkey_speed.c
crypt_burn_SOURCES = crypt_burn.c
fetch_SOURCES = fetch.c
id2sql_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
key2keyid_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
keyid2sql_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
oid2der_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
dh_speed_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lrt
pubkey_speed_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lrt
crypt_burn_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
fetch_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

key2keyid.o :	$(top_builddir)/config.status

keyid2sql.o :	$(top_builddir)/config.status
