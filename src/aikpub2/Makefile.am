bin_PROGRAMS = aikpub2

aikpub2_SOURCES = aikpub2.c

aikpub2_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libtpmtss/libtpmtss.la

aikpub2.o :	$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libtpmtss \
	-DIPSEC_CONFDIR=\"${sysconfdir}\" \
	-DPLUGINS=\""${aikgen_plugins}\""
