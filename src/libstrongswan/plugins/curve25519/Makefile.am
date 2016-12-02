AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) \
	@COVERAGE_CFLAGS@

# these files are also used by the tests, we can't directly refer to them
# because of the subdirectory, which would cause distclean to fail
noinst_LTLIBRARIES = libcurve25519.la
libcurve25519_la_SOURCES = \
	curve25519_private_key.h curve25519_private_key.c \
	curve25519_public_key.h curve25519_public_key.c \
	ref10/ref10.h ref10/ref10.c ref10/base.h ref10/base2.h

if MONOLITHIC
noinst_LTLIBRARIES += libstrongswan-curve25519.la
else
plugin_LTLIBRARIES = libstrongswan-curve25519.la
endif

libstrongswan_curve25519_la_SOURCES = \
	curve25519_dh.h curve25519_dh.c \
	curve25519_drv.h curve25519_drv.c \
	curve25519_drv_portable.h curve25519_drv_portable.c \
	curve25519_plugin.h curve25519_plugin.c

libstrongswan_curve25519_la_LDFLAGS = -module -avoid-version

libstrongswan_curve25519_la_LIBADD = libcurve25519.la

