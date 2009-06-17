
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-test-vectors.la

libstrongswan_test_vectors_la_SOURCES = \
	test_vectors_plugin.h test_vectors_plugin.c test_vectors.h \
	test_vectors/3des_cbc.c \
	test_vectors/aes_cbc.c \
	test_vectors/aes_xcbc.c \
	test_vectors/blowfish.c \
	test_vectors/camellia_cbc.c \
	test_vectors/md5.c \
	test_vectors/md5_hmac.c \
	test_vectors/sha1.c \
	test_vectors/sha1_hmac.c \
	test_vectors/sha2.c \
	test_vectors/sha2_hmac.c \
	test_vectors/fips_prf.c \
	test_vectors/rng.c
libstrongswan_test_vectors_la_LDFLAGS = -module

