ipsec_PROGRAMS = charon-nm

charon_nm_SOURCES = \
charon-nm.c

INCLUDES = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DIPSEC_PIDDIR=\"${piddir}\" \
	-DPLUGINS=\""${nm_plugins}\""

charon_nm_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	-lm $(PTHREADLIB) $(DLLIB)
