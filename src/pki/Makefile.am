ipsec_PROGRAMS = pki

pki_SOURCES = pki.c pki.h command.c command.h \
	commands/verify.c commands/issue.c commands/self.c \
	commands/keyid.c commands/pub.c commands/gen.c

pki_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = \
	-DPLUGINS=\""${libstrongswan_plugins}\"" \
	-DSTRONGSWAN_CONF=\"${strongswan_conf}\"
