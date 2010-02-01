
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-eap-tls.la

libstrongswan_eap_tls_la_SOURCES = eap_tls_plugin.h eap_tls_plugin.c \
	eap_tls.h eap_tls.c tls/tls.h tls/tls.c \
	tls/tls_protection.h tls/tls_protection.c \
	tls/tls_compression.h tls/tls_compression.c \
	tls/tls_fragmentation.h tls/tls_fragmentation.c \
	tls/tls_crypto.h tls/tls_crypto.c \
	tls/tls_reader.h tls/tls_reader.c \
	tls/tls_writer.h tls/tls_writer.c \
	tls/tls_peer.h tls/tls_peer.c \
	tls/tls_server.h tls/tls_server.c \
	tls/tls_handshake.h
libstrongswan_eap_tls_la_LDFLAGS = -module -avoid-version
