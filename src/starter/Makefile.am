ipsec_PROGRAMS = starter
starter_SOURCES = y.tab.c netkey.c y.tab.h parser.h args.h netkey.h \
starterwhack.c starterwhack.h starterstroke.c invokepluto.c confread.c \
starterstroke.h interfaces.c invokepluto.h confread.h interfaces.h args.c \
keywords.c files.h keywords.h cmp.c starter.c cmp.h exec.c invokecharon.c \
exec.h invokecharon.h lex.yy.c loglite.c klips.c klips.h

INCLUDES = \
-I${linux_headers} \
-I$(top_srcdir)/src/libstrongswan \
-I$(top_srcdir)/src/libfreeswan \
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
-DDEBUG

starter_LDADD = defs.o $(top_builddir)/src/libfreeswan/libfreeswan.a $(top_builddir)/src/libstrongswan/libstrongswan.la $(SOCKLIB)
EXTRA_DIST = parser.l parser.y keywords.txt ipsec.conf
dist_man_MANS = ipsec.conf.5 starter.8
MAINTAINERCLEANFILES = lex.yy.c y.tab.c y.tab.h keywords.c

PLUTODIR=$(top_srcdir)/src/pluto
SCEPCLIENTDIR=$(top_srcdir)/src/scepclient

if USE_PLUTO
  AM_CFLAGS += -DSTART_PLUTO
endif

if USE_CHARON
  AM_CFLAGS += -DSTART_CHARON
endif

lex.yy.c:	$(srcdir)/parser.l $(srcdir)/parser.y $(srcdir)/parser.h
		$(LEX) $(srcdir)/parser.l

y.tab.c:	$(srcdir)/parser.y $(srcdir)/parser.l $(srcdir)/parser.h
		$(YACC) -v -d $(srcdir)/parser.y

y.tab.h:	$(srcdir)/parser.y $(srcdir)/parser.l $(srcdir)/parser.h
		$(YACC) -v -d $(srcdir)/parser.y

keywords.c:	$(srcdir)/keywords.txt $(srcdir)/keywords.h
		$(GPERF) -m 10 -C -G -D -t < $(srcdir)/keywords.txt > $@

defs.o:		$(PLUTODIR)/defs.c $(PLUTODIR)/defs.h
		$(COMPILE) -c -o $@ $(PLUTODIR)/defs.c

install-exec-local :
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d "$(DESTDIR)$(sysconfdir)/ipsec.d" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/cacerts" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/cacerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/ocspcerts" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/ocspcerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/certs" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/certs" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/acerts" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/acerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/aacerts" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/aacerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/crls" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/crls" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/reqs" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/reqs" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/private" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -d -m 750 "$(DESTDIR)$(sysconfdir)/ipsec.d/private" || true
		test -e "$(DESTDIR)$(sysconfdir)/ipsec.conf" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -m 644 $(srcdir)/ipsec.conf $(DESTDIR)$(sysconfdir)/ipsec.conf || true

