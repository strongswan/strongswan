ipsec_PROGRAMS = pki

pki_SOURCES = pki.c pki.h command.c command.h \
	commands/gen.c commands/pub.c commands/keyid.c \
	commands/self.c commands/issue.c commands/verify.c
pki_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
	-DPLUGINDIR=\"${plugindir}\" \
	-DPLUGINS=\""${libstrongswan_plugins}\"" \
	-DSTRONGSWAN_CONF=\"${strongswan_conf}\"
