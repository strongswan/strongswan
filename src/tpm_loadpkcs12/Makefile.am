bin_PROGRAMS = tpm_loadpkcs12

tpm_loadpkcs12_SOURCES = tpm_loadpkcs12.c

tpm_loadpkcs12_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libtpmtss/libtpmtss.la

tpm_loadpkcs12.o :	$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libtpmtss \
	-DIPSEC_CONFDIR=\"${sysconfdir}\"
