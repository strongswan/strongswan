AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-DIPSEC_PIDDIR=\"${piddir}\"

AM_CFLAGS = \
	-rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-vici.la
else
plugin_LTLIBRARIES = libstrongswan-vici.la
endif

libstrongswan_vici_la_SOURCES = \
	vici_socket.h vici_socket.c \
	vici_message.h vici_message.c \
	vici_builder.h vici_builder.c \
	vici_dispatcher.h vici_dispatcher.c \
	vici_plugin.h vici_plugin.c

libstrongswan_vici_la_LDFLAGS = -module -avoid-version

TESTS = vici_tests

check_PROGRAMS = $(TESTS)

vici_tests_SOURCES = \
	suites/test_socket.c \
	suites/test_message.c \
	vici_socket.c \
	vici_message.c \
	vici_builder.c \
	vici_tests.h vici_tests.c

vici_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	@COVERAGE_CFLAGS@

vici_tests_LDFLAGS = @COVERAGE_LDFLAGS@
vici_tests_LDADD = \
	$(top_builddir)/src/libcharon/libcharon.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la
