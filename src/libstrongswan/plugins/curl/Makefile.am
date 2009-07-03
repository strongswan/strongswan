
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-curl.la

libstrongswan_curl_la_SOURCES = curl_plugin.h curl_plugin.c curl_fetcher.c curl_fetcher.h
libstrongswan_curl_la_LDFLAGS = -module -avoid-version
libstrongswan_curl_la_LIBADD  = -lcurl

