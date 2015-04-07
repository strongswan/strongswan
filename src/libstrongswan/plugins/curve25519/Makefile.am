AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-curve25519.la
else
plugin_LTLIBRARIES = libstrongswan-curve25519.la
endif

libstrongswan_curve25519_la_SOURCES = \
	curve25519_dh.h curve25519_dh.c \
	curve25519_drv.h curve25519_drv.c \
	curve25519_drv_portable.h curve25519_drv_portable.c \
	curve25519_plugin.h curve25519_plugin.c

libstrongswan_curve25519_la_LDFLAGS = -module -avoid-version
