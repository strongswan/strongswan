sbin_PROGRAMS = swanctl

conffile = `dirname $(strongswan_conf)`/strongswan.d/swanctl.conf

swanctl_SOURCES = \
	command.c command.h \
	commands/initiate.c \
	commands/terminate.c \
	commands/install.c \
	commands/version.c \
	commands/list_sas.c \
	commands/list_pols.c \
	commands/load_conns.c \
	swanctl.c

swanctl_LDADD = \
	$(top_builddir)/src/libcharon/plugins/vici/libvici.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

swanctl.o :		$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon/plugins/vici \
	-DCONF_FILE=\""${conffile}\"" \
	-DPLUGINS=\""${s_plugins}\""
