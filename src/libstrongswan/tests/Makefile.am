TESTS = test_runner

check_PROGRAMS = $(TESTS)

test_runner_SOURCES = \
  test_runner.c test_runner.h \
  test_linked_list.c test_enumerator.c test_linked_list_enumerator.c \
  test_chunk.c test_hashtable.c test_identification.c \
  test_threading.c


test_runner_CFLAGS = \
  -I$(top_srcdir)/src/libstrongswan \
  @CHECK_CFLAGS@

test_runner_LDADD = \
  $(top_builddir)/src/libstrongswan/libstrongswan.la \
  @CHECK_LIBS@
