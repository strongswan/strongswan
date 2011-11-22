ipsec_PROGRAMS = starter
starter_SOURCES = \
parser.y lexer.l ipsec-parser.h netkey.c args.h netkey.h \
starterwhack.c starterwhack.h starterstroke.c invokepluto.c confread.c \
starterstroke.h interfaces.c invokepluto.h confread.h interfaces.h args.c \
keywords.c files.h keywords.h cmp.c starter.c cmp.h exec.c invokecharon.c \
exec.h invokecharon.h loglite.c klips.c klips.h

INCLUDES = \
-I${linux_headers} \
-I$(top_srcdir)/src/libstrongswan \
-I$(top_srcdir)/src/libfreeswan \
-I$(top_srcdir)/src/libhydra \
-I$(top_srcdir)/src/pluto \
-I$(top_srcdir)/src/whack \
-I$(top_srcdir)/src/stroke

AM_CFLAGS = \
-DIPSEC_DIR=\"${ipsecdir}\" \
-DIPSEC_CONFDIR=\"${sysconfdir}\" \
-DIPSEC_PIDDIR=\"${piddir}\" \
-DIPSEC_EAPDIR=\"${eapdir}\" \
-DDEV_RANDOM=\"${random_device}\" \
-DDEV_URANDOM=\"${urandom_device}\" \
-DPLUGINS=\""${starter_plugins}\"" \
-DDEBUG

AM_YFLAGS = -v -d

starter_LDADD = defs.o $(top_builddir)/src/libfreeswan/libfreeswan.a $(top_builddir)/src/libstrongswan/libstrongswan.la $(top_builddir)/src/libhydra/libhydra.la $(SOCKLIB)
EXTRA_DIST = keywords.txt ipsec.conf Android.mk
MAINTAINERCLEANFILES = keywords.c
BUILT_SOURCES = parser.h

PLUTODIR=$(top_srcdir)/src/pluto
SCEPCLIENTDIR=$(top_srcdir)/src/scepclient

if USE_PLUTO
  AM_CFLAGS += -DSTART_PLUTO
endif

if USE_CHARON
  AM_CFLAGS += -DSTART_CHARON
endif

if USE_LOAD_WARNING
  AM_CFLAGS += -DLOAD_WARNING
endif

if USE_TOOLS
  AM_CFLAGS += -DGENERATE_SELFCERT
endif

keywords.c:	$(srcdir)/keywords.txt $(srcdir)/keywords.h
		$(GPERF) -m 10 -C -G -D -t < $(srcdir)/keywords.txt > $@

defs.o:		$(PLUTODIR)/defs.c $(PLUTODIR)/defs.h
		$(COMPILE) -c -o $@ $(PLUTODIR)/defs.c

install-exec-local :
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d" || $(INSTALL) -o -d "$(DESTDIR)$(sysconfdir)/ipsec.d" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/cacerts" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)/ipsec.d/cacerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/ocspcerts" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)/ipsec.d/ocspcerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/certs" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)/ipsec.d/certs" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/acerts" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)/ipsec.d/acerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/aacerts" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)/ipsec.d/aacerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/crls" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)/ipsec.d/crls" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/reqs" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)/ipsec.d/reqs" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/private" || $(INSTALL) -d -m 750 "$(DESTDIR)$(sysconfdir)/ipsec.d/private" || true
		test -e "$(DESTDIR)$(sysconfdir)/ipsec.conf" || $(INSTALL) -m 644 $(srcdir)/ipsec.conf $(DESTDIR)$(sysconfdir)/ipsec.conf || true

