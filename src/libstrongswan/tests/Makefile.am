TESTS = test_runner

check_PROGRAMS = $(TESTS)

test_runner_SOURCES = \
  test_runner.c test_runner.h test_suite.h \
  test_linked_list.c test_enumerator.c test_linked_list_enumerator.c \
  test_bio_reader.c test_bio_writer.c test_chunk.c test_enum.c test_hashtable.c \
  test_identification.c test_threading.c test_utils.c test_vectors.c \
  test_array.c test_ecdsa.c test_rsa.c test_host.c test_printf.c

test_runner_CFLAGS = \
  -I$(top_srcdir)/src/libstrongswan \
  -DPLUGINDIR=\""$(top_builddir)/src/libstrongswan/plugins\"" \
  -DPLUGINS=\""${s_plugins}\"" \
  @COVERAGE_CFLAGS@ \
  @CHECK_CFLAGS@

test_runner_LDFLAGS = @COVERAGE_LDFLAGS@
test_runner_LDADD = \
  $(top_builddir)/src/libstrongswan/libstrongswan.la \
  $(PTHREADLIB) \
  @CHECK_LIBS@
