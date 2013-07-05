
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtls

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tls-stream.la
else
plugin_LTLIBRARIES = libstrongswan-tls-stream.la
libstrongswan_tls_stream_la_LIBADD = $(top_builddir)/src/libtls/libtls.la
endif

libstrongswan_tls_stream_la_SOURCES = \
	tls_stream_plugin.h tls_stream_plugin.c \
	tls_stream.h tls_stream.c \
	tls_stream_service.h tls_stream_service.c

libstrongswan_tls_stream_la_LDFLAGS = -module -avoid-version
