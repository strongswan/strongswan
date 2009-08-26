ipsec_PROGRAMS = pki

pki_SOURCES = pki.c
pki_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
	-DPLUGINDIR=\"${plugindir}\" \
	-DPLUGINS=\""${libstrongswan_plugins}\"" \
	-DSTRONGSWAN_CONF=\"${strongswan_conf}\"
