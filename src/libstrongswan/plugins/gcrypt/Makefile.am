
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-gcrypt.la

libstrongswan_gcrypt_la_SOURCES = gcrypt_plugin.h gcrypt_plugin.c \
	gcrypt_rng.h gcrypt_rng.c \
	gcrypt_crypter.h gcrypt_crypter.c \
	gcrypt_hasher.h gcrypt_hasher.c

libstrongswan_gcrypt_la_LDFLAGS = -module
libstrongswan_gcrypt_la_LIBADD  = -lgcrypt

