ipsec_PROGRAMS = openac
openac_SOURCES = openac.c
dist_man_MANS = openac.8

INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
  -DIPSEC_CONFDIR=\"${sysconfdir}\" \
  -DPLUGINS=\""${openac_plugins}\""
openac_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
openac.o :		$(top_builddir)/config.status
