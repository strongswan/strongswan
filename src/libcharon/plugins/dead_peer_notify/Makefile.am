AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-dead-peer-notify.la
else
plugin_LTLIBRARIES = libstrongswan-dead-peer-notify.la
endif

libstrongswan_dead_peer_notify_la_SOURCES = \
	dead_peer_notify_plugin.h dead_peer_notify_plugin.c \
	dead_peer_notify_listener.h dead_peer_notify_listener.c \
	dead_peer_notify_mail.h dead_peer_notify_mail.c \
	dead_peer_notify_exec.h dead_peer_notify_exec.c

libstrongswan_dead_peer_notify_la_LDFLAGS = -module -avoid-version
libstrongswan_dead_peer_notify_la_LIBADD  = -lcurl
