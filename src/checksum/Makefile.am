ipsec_LTLIBRARIES = libchecksum.la
noinst_PROGRAMS = checksum_builder

nodist_libchecksum_la_SOURCES = checksum.c

checksum_builder_SOURCES = checksum_builder.c
checksum_builder_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

BUILT_SOURCES = checksum.c
CLEANFILES = checksum.c
INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = -rdynamic

libs =	$(shell find $(top_builddir)/src/libstrongswan $(top_builddir)/src/charon \
			-name 'libstrongswan*.so')

if USE_CHARON
  libs += $(top_builddir)/src/charon/.libs/charon
endif

if USE_PLUTO
  libs += $(top_builddir)/src/pluto/.libs/pluto
endif

checksum.c : checksum_builder $(libs)
		./checksum_builder $(libs) > checksum.c
