lib_LTLIBRARIES = libdumm.la
ipsec_PROGRAMS = dumm

libdumm_la_SOURCES = dumm.c dumm.h guest.c guest.h iface.c iface.h bridge.c bridge.h mconsole.c mconsole.h cowfs.h cowfs.c
dumm_SOURCES = main.c

libdumm_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lpthread -lbridge -lfuse
dumm_LDADD = -ldumm -lreadline

INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -D_FILE_OFFSET_BITS=64
