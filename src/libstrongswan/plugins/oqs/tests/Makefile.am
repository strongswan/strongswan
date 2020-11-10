TESTS = oqs_tests

check_PROGRAMS = $(TESTS)

oqs_tests_SOURCES = \
	suites/test_oqs.c suites/test_oqs_sig.c \
	oqs_tests.h oqs_tests.c

oqs_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-I$(top_srcdir)/src/libstrongswan/plugins/oqs \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS=\""${s_plugins}\"" \
	@COVERAGE_CFLAGS@

oqs_tests_LDFLAGS = @COVERAGE_LDFLAGS@
oqs_tests_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	../libqske-oqs.la
