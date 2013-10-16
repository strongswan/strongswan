TESTS = test_runner

check_PROGRAMS = $(TESTS)

test_runner_SOURCES = \
  test_runner.c test_runner.h test_suite.c test_suite.h \
  suites/test_linked_list.c \
  suites/test_enumerator.c \
  suites/test_linked_list_enumerator.c \
  suites/test_bio_reader.c \
  suites/test_bio_writer.c \
  suites/test_chunk.c \
  suites/test_enum.c \
  suites/test_hashtable.c \
  suites/test_identification.c \
  suites/test_threading.c \
  suites/test_watcher.c \
  suites/test_stream.c \
  suites/test_utils.c \
  suites/test_vectors.c \
  suites/test_array.c \
  suites/test_ecdsa.c \
  suites/test_rsa.c \
  suites/test_host.c \
  suites/test_pen.c \
  suites/test_asn1.c \
  suites/test_printf.c

test_runner_CFLAGS = \
  -I$(top_srcdir)/src/libstrongswan \
  -DPLUGINDIR=\""$(top_builddir)/src/libstrongswan/plugins\"" \
  -DPLUGINS=\""${s_plugins}\"" \
  @COVERAGE_CFLAGS@

test_runner_LDFLAGS = @COVERAGE_LDFLAGS@
test_runner_LDADD = \
  $(top_builddir)/src/libstrongswan/libstrongswan.la \
  $(PTHREADLIB)
