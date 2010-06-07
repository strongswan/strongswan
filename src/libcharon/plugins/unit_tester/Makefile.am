
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-unit-tester.la
else
plugin_LTLIBRARIES = libstrongswan-unit-tester.la
endif

libstrongswan_unit_tester_la_SOURCES = \
	unit_tester.c unit_tester.h tests.h \
	tests/test_enumerator.c \
	tests/test_auth_info.c \
	tests/test_curl.c \
	tests/test_mysql.c \
	tests/test_sqlite.c \
	tests/test_mutex.c \
	tests/test_rsa_gen.c \
	tests/test_cert.c \
	tests/test_med_db.c \
	tests/test_chunk.c \
	tests/test_pool.c \
	tests/test_agent.c \
	tests/test_id.c \
	tests/test_hashtable.c

libstrongswan_unit_tester_la_LDFLAGS = -module -avoid-version
