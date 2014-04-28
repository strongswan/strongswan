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
	commands/list_pools.c \
	commands/load_conns.c \
	commands/load_creds.c \
	commands/load_pools.c \
	commands/log.c \
	commands/version.c \
	swanctl.c swanctl.h

swanctl_LDADD = \
	$(top_builddir)/src/libcharon/plugins/vici/libvici.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la

swanctl.o :		$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon/plugins/vici \
	-DSWANCTLDIR=\""${swanctldir}\"" \
	-DPLUGINS=\""${s_plugins}\""

man_MANS = \
	swanctl.8 \
	swanctl.conf.5

BUILT_SOURCES = swanctl.conf swanctl.conf.5.main
EXTRA_DIST = swanctl.opt swanctl.conf swanctl.conf.5.main
CLEANFILES = $(man_MANS)

.opt.conf:
	$(AM_V_GEN) \
	$(PYTHON) $(top_srcdir)/conf/format-options.py -f conf $< > $(srcdir)/$@

swanctl.conf.5.main: swanctl.opt
	$(AM_V_GEN) \
	$(PYTHON) $(top_srcdir)/conf/format-options.py -f man $< > $(srcdir)/$@

swanctl.conf.5: swanctl.conf.5.head swanctl.conf.5.main swanctl.conf.5.tail
	$(AM_V_GEN) \
	cat swanctl.conf.5.head $(srcdir)/swanctl.conf.5.main swanctl.conf.5.tail > $@

maintainer-clean-local:
	cd $(srcdir) && rm -f swanctl.conf swanctl.conf.5.main

install-data-local: swanctl.conf
	test -e "$(DESTDIR)$(swanctldir)" || $(INSTALL) -d "$(DESTDIR)$(swanctldir)"
	test -e "$(DESTDIR)$(swanctldir)/swanctl.conf" || $(INSTALL) -m 640 $(srcdir)/swanctl.conf $(DESTDIR)$(swanctldir)/swanctl.conf || true
