AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	-rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-ntru.la
else
plugin_LTLIBRARIES = libstrongswan-ntru.la
endif

libstrongswan_ntru_la_SOURCES = \
	ntru_plugin.h ntru_plugin.c \
	ntru_ke.h ntru_ke.c \
	ntru_crypto/ntru_crypto.h ntru_crypto/ntru_crypto_error.h \
	ntru_crypto/ntru_crypto_drbg.h ntru_crypto/ntru_crypto_drbg.c \
	ntru_crypto/ntru_crypto_hash_basics.h \
	ntru_crypto/ntru_crypto_hash.h ntru_crypto/ntru_crypto_hash.c \
	ntru_crypto/ntru_crypto_hmac.h ntru_crypto/ntru_crypto_hmac.c \
	ntru_crypto/ntru_crypto_msbyte_uint32.h \
	ntru_crypto/ntru_crypto_msbyte_uint32.c \
	ntru_crypto/ntru_crypto_ntru_convert.h \
	ntru_crypto/ntru_crypto_ntru_convert.c \
	ntru_crypto/ntru_crypto_ntru_encrypt.c \
	ntru_crypto/ntru_crypto_ntru_encrypt_key.h \
	ntru_crypto/ntru_crypto_ntru_encrypt_key.c \
	ntru_crypto/ntru_crypto_ntru_encrypt_param_sets.h \
	ntru_crypto/ntru_crypto_ntru_encrypt_param_sets.c \
	ntru_crypto/ntru_crypto_ntru_mgf1.h ntru_crypto/ntru_crypto_ntru_mgf1.c \
	ntru_crypto/ntru_crypto_ntru_poly.h ntru_crypto/ntru_crypto_ntru_poly.c \
	ntru_crypto/ntru_crypto_platform.h ntru_crypto/ntru_crypto_sha.h\
	ntru_crypto/ntru_crypto_sha1.h ntru_crypto/ntru_crypto_sha1.c\
	ntru_crypto/ntru_crypto_sha2.h ntru_crypto/ntru_crypto_sha2.c\
	ntru_crypto/ntru_crypto_sha256.h ntru_crypto/ntru_crypto_sha256.c

libstrongswan_ntru_la_LDFLAGS = -module -avoid-version


