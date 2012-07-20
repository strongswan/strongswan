
INCLUDES = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libimcv \
	-I$(top_srcdir)/src/libpts

AM_CFLAGS = -rdynamic -DPLUGINS=\""${attest_plugins}\""

imcv_LTLIBRARIES = imv-attestation.la

imv_attestation_la_LIBADD = \
	$(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libpts/libpts.la

imv_attestation_la_SOURCES = imv_attestation.c \
	imv_attestation_state.h imv_attestation_state.c \
	imv_attestation_process.h imv_attestation_process.c \
	imv_attestation_build.h imv_attestation_build.c

imv_attestation_la_LDFLAGS = -module -avoid-version

ipsec_PROGRAMS = attest
attest_SOURCES = attest.c \
	attest_usage.h attest_usage.c \
	attest_db.h attest_db.c \
	tables.sql data.sql
attest_LDADD = \
	$(top_builddir)/src/libimcv/libimcv.la \
	$(top_builddir)/src/libpts/libpts.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la
attest.o :	$(top_builddir)/config.status

EXTRA_DIST = build-database.sh
