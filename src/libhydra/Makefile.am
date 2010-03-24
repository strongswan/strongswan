lib_LTLIBRARIES = libhydra.la

libhydra_la_SOURCES =

libhydra_la_LIBADD =

#INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
-DIPSEC_DIR=\"${ipsecdir}\" \
-DPLUGINDIR=\"${plugindir}\" \
-DSTRONGSWAN_CONF=\"${strongswan_conf}\"

#EXTRA_DIST = Android.mk

# build optional plugins
########################

if MONOLITHIC
SUBDIRS =
else
SUBDIRS = .
endif

#if USE_FOO
#  SUBDIRS += plugins/foo
#if MONOLITHIC
#  libhydra_la_LIBADD += plugins/foo/libstrongswan-foo.la
#endif
#endif

