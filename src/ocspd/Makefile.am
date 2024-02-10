sbin_PROGRAMS = ocspd

ocspd_SOURCES = ocspd.c

ocspd.o :	$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-DPLUGINS="\"pem pkcs1 x509 openssl wolfssl\""

ocspd_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

man8_MANS = ocspd.8

CLEANFILES = $(man8_MANS)
