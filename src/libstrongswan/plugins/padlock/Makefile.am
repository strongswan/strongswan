
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-padlock.la

libstrongswan_padlock_la_SOURCES = padlock_plugin.h padlock_plugin.c \
	padlock_aes_crypter.c padlock_aes_crypter.h \
	padlock_sha1_hasher.c padlock_sha1_hasher.h
libstrongswan_padlock_la_LDFLAGS = -module

