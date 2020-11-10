AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

# these files are also used by the tests, we can't directly refer to them
# because of the subdirectory, which would cause distclean to fail
noinst_LTLIBRARIES = libqske-oqs.la
libqske_oqs_la_SOURCES = \
	oqs_kem.h oqs_kem.c oqs_drbg.h oqs_drbg.c \
	oqs_public_key.h oqs_public_key.c \
	oqs_private_key.h oqs_private_key.c

libqske_oqs_la_LIBADD = \
	-loqs -lcrypto -lm

if MONOLITHIC
noinst_LTLIBRARIES += libstrongswan-oqs.la
else
plugin_LTLIBRARIES = libstrongswan-oqs.la
endif

libstrongswan_oqs_la_SOURCES = \
	oqs_plugin.h oqs_plugin.c

libstrongswan_oqs_la_LDFLAGS = -module -avoid-version

libstrongswan_oqs_la_LIBADD  = libqske-oqs.la
