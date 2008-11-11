ipsec_PROGRAMS = starter
starter_SOURCES = y.tab.c netkey.c y.tab.h parser.h args.h netkey.h \
starterwhack.c starterwhack.h starterstroke.c invokepluto.c confread.c \
starterstroke.h interfaces.c invokepluto.h confread.h interfaces.h args.c \
keywords.c files.h keywords.h cmp.c starter.c cmp.h exec.c invokecharon.c \
exec.h invokecharon.h lex.yy.c loglite.c klips.c klips.h

INCLUDES = -I$(top_srcdir)/src/libfreeswan -I$(top_srcdir)/src/pluto -I$(top_srcdir)/src/whack -I$(top_srcdir)/src/stroke
AM_CFLAGS = -DIPSEC_DIR=\"${ipsecdir}\" -DIPSEC_CONFDIR=\"${confdir}\" -DIPSEC_PIDDIR=\"${piddir}\" -DIPSEC_EAPDIR=\"${eapdir}\" -DDEBUG
starter_LDADD = defs.o $(top_builddir)/src/libfreeswan/libfreeswan.a
EXTRA_DIST = parser.l parser.y keywords.txt ipsec.conf
dist_man_MANS = ipsec.conf.5 starter.8
MAINTAINERCLEANFILES = lex.yy.c y.tab.c y.tab.h keywords.c

PLUTODIR=$(top_srcdir)/src/pluto
SCEPCLIENTDIR=$(top_srcdir)/src/scepclient

lex.yy.c:	parser.l parser.y parser.h y.tab.c
		$(LEX) --nounput $< 

y.tab.c:	parser.y parser.l parser.h
		$(YACC) -v -d $<

y.tab.h:	parser.y parser.l parser.h
		$(YACC) -v -d $<

keywords.c:	keywords.txt keywords.h
		$(GPERF) -C -G -t < $< > $@

defs.o:		$(PLUTODIR)/defs.c $(PLUTODIR)/defs.h
		$(COMPILE) -c -o $@ $<

install-exec-local :	
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/cacerts" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/cacerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/ocspcerts" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/ocspcerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/certs" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/certs" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/acerts" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/acerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/aacerts" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/aacerts" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/crls" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/crls" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/reqs" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/reqs" || true
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/private" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d -m 750 "$(DESTDIR)$(sysconfdir)/ipsec.d/private" || true
		test -e "$(DESTDIR)$(sysconfdir)/ipsec.conf" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -m 644 ipsec.conf $(DESTDIR)$(sysconfdir)/ipsec.conf || true

