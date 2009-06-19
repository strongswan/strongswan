ipsec_LTLIBRARIES = libchecksum.la
noinst_PROGRAMS = checksum_builder

libchecksum_la_SOURCES = checksum.c

checksum_builder_SOURCES = checksum_builder.c
checksum_builder_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

BUILT_SOURCES = checksum.c
CLEANFILES = checksum.c checksum_builder
INCLUDES = -I$(top_srcdir)/src/libstrongswan

libs = $(shell find $(top_builddir)/src/libstrongswan -name 'libstrongswan*.so')

checksum.c : checksum_builder $(libs)
		./checksum_builder $(libs) > checksum.c
