
INCLUDES = -I$(top_srcdir)/src/libstrongswan

ipseclib_LTLIBRARIES = libtls.la
libtls_la_SOURCES = \
	tls_protection.c tls_compression.c tls_fragmentation.c tls_alert.c \
	tls_crypto.c tls_prf.c tls_socket.c tls_eap.c tls_cache.c tls_peer.c \
	tls_server.c tls.c

if USE_DEV_HEADERS
tls_includedir = ${dev_headers}/tls
nobase_tls_include_HEADERS = \
	tls_protection.h tls_compression.h tls_fragmentation.h tls_alert.h \
	tls_crypto.h tls_prf.h tls_socket.h tls_eap.h tls_cache.h tls_peer.h \
	tls_server.h tls_handshake.h tls_application.h tls.h
endif
