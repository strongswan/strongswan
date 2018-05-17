bin_PROGRAMS = tpm_seal

tpm_seal_SOURCES = tpm_seal.c

tpm_seal_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libtpmtss/libtpmtss.la

tpm_seal.o :	$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libtpmtss \
	-DIPSEC_CONFDIR=\"${sysconfdir}\"
