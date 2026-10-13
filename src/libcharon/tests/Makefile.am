TESTS = libcharon_tests exchange_tests

check_PROGRAMS = $(TESTS)

libcharon_tests_SOURCES = \
  suites/test_ike_cfg.c \
  suites/test_peer_cfg.c \
  suites/test_mem_pool.c \
  suites/test_message_chapoly.c \
  libcharon_tests.h libcharon_tests.c

if USE_IKEV2
check_PROGRAMS += fortigate_helper_probe
fortigate_helper_probe_SOURCES = utils/fortigate_helper_probe.c

libcharon_tests_SOURCES += \
  suites/test_eap_fortigate.c \
  ../plugins/eap_identity/eap_identity.c \
  ../plugins/eap_gtc/eap_gtc.c
endif

libcharon_tests_CFLAGS = \
  -DTEST_HELPER_PROBE=\""$(abs_builddir)/fortigate_helper_probe"\" \
  -I$(top_srcdir)/src/libcharon \
  -I$(top_srcdir)/src/libstrongswan \
  -I$(top_srcdir)/src/libstrongswan/tests \
  -DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
  -DPLUGINS=\""${s_plugins}\"" \
  @COVERAGE_CFLAGS@

libcharon_tests_LDFLAGS = @COVERAGE_LDFLAGS@
libcharon_tests_LDADD = \
  $(top_builddir)/src/libcharon/libcharon.la \
  $(top_builddir)/src/libstrongswan/libstrongswan.la \
  $(top_builddir)/src/libstrongswan/tests/libtest.la


exchange_tests_SOURCES = \
  suites/test_child_create.c \
  suites/test_child_delete.c \
  suites/test_child_rekey.c \
  suites/test_ike_delete.c \
  suites/test_ike_mid_sync.c \
  suites/test_ike_rekey.c \
  suites/test_childless.c \
  utils/exchange_test_asserts.h utils/exchange_test_asserts.c \
  utils/exchange_test_helper.h utils/exchange_test_helper.c \
  utils/job_asserts.h \
  utils/mock_eap.h utils/mock_eap.c \
  utils/mock_dh.h utils/mock_dh.c \
  utils/mock_ipsec.h utils/mock_ipsec.c \
  utils/mock_net.h utils/mock_net.c \
  utils/mock_nonce_gen.h utils/mock_nonce_gen.c \
  utils/mock_sender.h utils/mock_sender.c \
  utils/sa_asserts.h \
  exchange_tests.h exchange_tests.c

if USE_IKEV2
exchange_tests_SOURCES += suites/test_fortigate_initial_contact.c
endif

exchange_tests_CFLAGS = \
  -I$(top_srcdir)/src/libcharon \
  -I$(top_srcdir)/src/libstrongswan \
  -I$(top_srcdir)/src/libstrongswan/tests \
  -DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
  -DPLUGINS=\""${s_plugins}\"" \
  @COVERAGE_CFLAGS@

exchange_tests_LDFLAGS = @COVERAGE_LDFLAGS@
exchange_tests_LDADD = \
  $(top_builddir)/src/libcharon/libcharon.la \
  $(top_builddir)/src/libstrongswan/libstrongswan.la \
  $(top_builddir)/src/libstrongswan/tests/libtest.la
