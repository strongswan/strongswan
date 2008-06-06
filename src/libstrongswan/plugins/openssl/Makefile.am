
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-openssl.la

libstrongswan_openssl_la_SOURCES = openssl_plugin.h openssl_plugin.c \
	openssl_crypter.c openssl_crypter.h \
	openssl_hasher.c openssl_hasher.h \
	openssl_diffie_hellman.c openssl_diffie_hellman.h \
	openssl_rsa_private_key.c openssl_rsa_private_key.h \
	openssl_rsa_public_key.c openssl_rsa_public_key.h \
	openssl_ec_diffie_hellman.c openssl_ec_diffie_hellman.h

libstrongswan_openssl_la_LDFLAGS = -module
libstrongswan_openssl_la_LIBADD  = -lcrypto

