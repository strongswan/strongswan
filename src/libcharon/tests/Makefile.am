TESTS = libcharon_tests

check_PROGRAMS = $(TESTS)

libcharon_tests_SOURCES = \
  suites/test_ike_cfg.c \
  suites/test_mem_pool.c \
  suites/test_message_chapoly.c \
  libcharon_tests.h libcharon_tests.c

libcharon_tests_CFLAGS = \
  -I$(top_srcdir)/src/libcharon \
  -I$(top_srcdir)/src/libhydra \
  -I$(top_srcdir)/src/libstrongswan \
  -I$(top_srcdir)/src/libstrongswan/tests \
  -DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
  -DPLUGINS=\""${s_plugins}\"" \
  @COVERAGE_CFLAGS@

libcharon_tests_LDFLAGS = @COVERAGE_LDFLAGS@
libcharon_tests_LDADD = \
  $(top_builddir)/src/libcharon/libcharon.la \
  $(top_builddir)/src/libhydra/libhydra.la \
  $(top_builddir)/src/libstrongswan/libstrongswan.la \
  $(top_builddir)/src/libstrongswan/tests/libtest.la
