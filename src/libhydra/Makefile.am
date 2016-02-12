ipseclib_LTLIBRARIES = libhydra.la

libhydra_la_SOURCES = \
hydra.c hydra.h

libhydra_la_LIBADD = \
  $(top_builddir)/src/libstrongswan/libstrongswan.la

if USE_WINDOWS
  libhydra_la_LIBADD += -lws2_32
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DPLUGINDIR=\"${plugindir}\"

AM_LDFLAGS = \
  -no-undefined

EXTRA_DIST = Android.mk

# build optional plugins
########################

if MONOLITHIC
SUBDIRS =
else
SUBDIRS = .
endif

if MONOLITHIC
  SUBDIRS += .
endif
SUBDIRS += tests
