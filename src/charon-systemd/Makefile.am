sbin_PROGRAMS = charon-systemd

charon_systemd_SOURCES = \
charon-systemd.c

charon-systemd.o :	$(top_builddir)/config.status

charon_systemd_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-DPLUGINS=\""${charon_plugins}\""

charon_systemd_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	-lsystemd-daemon -lsystemd-journal -lm $(PTHREADLIB) $(DLLIB)
