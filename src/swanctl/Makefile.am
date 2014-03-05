sbin_PROGRAMS = swanctl

swanctl_SOURCES = \
	command.c command.h \
	commands/initiate.c \
	commands/terminate.c \
	commands/install.c \
	commands/list_sas.c \
	commands/list_pols.c \
	commands/list_conns.c \
	commands/list_certs.c \
	commands/load_conns.c \
	commands/load_creds.c \
	commands/version.c \
	swanctl.c swanctl.h

swanctl_LDADD = \
	$(top_builddir)/src/libcharon/plugins/vici/libvici.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

swanctl.o :		$(top_builddir)/config.status

EXTRA_DIST = swanctl.conf

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon/plugins/vici \
	-DSWANCTLDIR=\""${swanctldir}\"" \
	-DPLUGINS=\""${s_plugins}\""
