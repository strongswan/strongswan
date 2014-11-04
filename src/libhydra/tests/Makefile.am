TESTS = hydra_tests

check_PROGRAMS = $(TESTS)

hydra_tests_SOURCES = \
  hydra_tests.h hydra_tests.c

hydra_tests_CFLAGS = \
  -I$(top_srcdir)/src/libhydra \
  -I$(top_srcdir)/src/libstrongswan \
  -I$(top_srcdir)/src/libstrongswan/tests \
  @COVERAGE_CFLAGS@

hydra_tests_LDFLAGS = @COVERAGE_LDFLAGS@
hydra_tests_LDADD = \
  $(top_builddir)/src/libhydra/libhydra.la \
  $(top_builddir)/src/libstrongswan/libstrongswan.la \
  $(top_builddir)/src/libstrongswan/tests/libtest.la
