sbin_PROGRAMS = swanctl

swanctl_SOURCES = \
	command.c command.h \
	commands/initiate.c \
	commands/terminate.c \
	commands/list_sas.c \
	swanctl.c

swanctl_LDADD = \
	$(top_builddir)/src/libcharon/plugins/vici/libvici.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

swanctl.o :		$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon/plugins/vici \
	-DPLUGINS=\""${s_plugins}\""
