if !USE_WINDOWS

sbin_PROGRAMS = oval-updater

AM_CFLAGS = \
	${xml_CFLAGS}

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-DPLUGINS=\""sqlite"\"

oval_updater_SOURCES = \
	oval-updater.c oval.h oval.c

oval_updater_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	${xml_LIBS}

oval-updater.o : $(top_builddir)/config.status

EXTRA_DIST = oval-updater.sh

man8_MANS = oval-updater.8
CLEANFILES = $(man8_MANS)

endif
