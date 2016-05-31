bin_PROGRAMS = aikpub2

aikpub2_SOURCES = aikpub2.c

aikpub2_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
aikpub2.o :	$(top_builddir)/config.status

if USE_TSS2
  aikpub2_LDADD += -ltctisocket -ltss2
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-DIPSEC_CONFDIR=\"${sysconfdir}\" \
	-DPLUGINS=\""${aikgen_plugins}\""
