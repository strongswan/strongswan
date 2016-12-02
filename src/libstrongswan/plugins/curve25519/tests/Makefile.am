TESTS = curve25519_tests

check_PROGRAMS = $(TESTS)

curve25519_tests_SOURCES = \
	suites/test_curve25519_ed25519.c \
	curve25519_tests.h curve25519_tests.c

curve25519_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-I$(top_srcdir)/src/libstrongswan/plugins/curve25519 \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS=\""${s_plugins}\"" \
	@COVERAGE_CFLAGS@

curve25519_tests_LDFLAGS = @COVERAGE_LDFLAGS@
curve25519_tests_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	../libcurve25519.la
