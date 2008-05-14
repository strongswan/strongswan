lib_LTLIBRARIES = libdumm.la
ipsec_PROGRAMS = dumm testing

libdumm_la_SOURCES = dumm.c dumm.h guest.c guest.h iface.c iface.h \
  bridge.c bridge.h mconsole.c mconsole.h cowfs.h cowfs.c
dumm_SOURCES = main.c
testing_SOURCES = testing.c

libdumm_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lbridge -lfuse -lutil
dumm_LDADD = -ldumm ${gtk_LIBS}
testing_LDADD = -ldumm

INCLUDES = -I$(top_srcdir)/src/libstrongswan ${gtk_CFLAGS}
AM_CFLAGS = -D_FILE_OFFSET_BITS=64
