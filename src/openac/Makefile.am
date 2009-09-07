ipsec_PROGRAMS = openac
openac_SOURCES = openac.c
dist_man_MANS = openac.8

INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
  -DIPSEC_CONFDIR=\"${sysconfdir}\" \
  -DSTRONGSWAN_CONF=\"${strongswan_conf}\" \
  -DIPSEC_PLUGINDIR=\"${plugindir}\" \
  -DPLUGINS=\""${libstrongswan_plugins}\""
openac_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

