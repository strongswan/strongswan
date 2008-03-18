
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libcharon-unit-tester.la

libcharon_unit_tester_la_SOURCES = unit_tester.c unit_tester.h \
  tests/test_enumerator.c \
  tests/test_auth_info.c \
  tests/test_fips_prf.c \
  tests/test_curl.c \
  tests/test_mysql.c \
  tests/test_sqlite.c \
  tests/test_mutex.c \
  tests/test_rsa_gen.c
libcharon_unit_tester_la_LDFLAGS = -module

