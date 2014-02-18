AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	-rdynamic @COVERAGE_CFLAGS@

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-ntru.la
else
plugin_LTLIBRARIES = libstrongswan-ntru.la
endif

libstrongswan_ntru_la_SOURCES = \
	ntru_plugin.h ntru_plugin.c \
	ntru_drbg.h ntru_drbg.c \
	ntru_ke.h ntru_ke.c \
	ntru_mgf1.h ntru_mgf1.c \
	ntru_poly.h ntru_poly.c \
	ntru_trits.h ntru_trits.c \
	ntru_crypto/ntru_crypto.h \
	ntru_crypto/ntru_crypto_ntru_convert.h \
	ntru_crypto/ntru_crypto_ntru_convert.c \
	ntru_crypto/ntru_crypto_ntru_encrypt.c \
	ntru_crypto/ntru_crypto_ntru_encrypt_key.h \
	ntru_crypto/ntru_crypto_ntru_encrypt_key.c \
	ntru_crypto/ntru_crypto_ntru_encrypt_param_sets.h \
	ntru_crypto/ntru_crypto_ntru_encrypt_param_sets.c \
	ntru_crypto/ntru_crypto_ntru_poly.h \
	ntru_crypto/ntru_crypto_ntru_poly.c

libstrongswan_ntru_la_LDFLAGS = -module -avoid-version


