ipsec_PROGRAMS = starter
starter_SOURCES = y.tab.c netkey.c y.tab.h parser.h args.h netkey.h \
starterwhack.c starterwhack.h starterstroke.c invokepluto.c confread.c \
starterstroke.h interfaces.c invokepluto.h confread.h  interfaces.h args.c \
keywords.c files.h keywords.h cmp.c starter.c cmp.h exec.c invokecharon.c \
exec.h invokecharon.h lex.yy.c loglite.c

INCLUDES = -I$(top_srcdir)/src/libfreeswan -I$(top_srcdir)/src/pluto -I$(top_srcdir)/src/whack -I$(top_srcdir)/src/stroke
AM_CFLAGS = -DIPSEC_DIR=\"${ipsecdir}\" -DIPSEC_CONFDIR=\"${confdir}\" -DIPSEC_PIDDIR=\"${piddir}\" -DIPSEC_EAPDIR=\"${eapdir}\" -DDEBUG
starter_LDADD = defs.o $(top_srcdir)/src/libfreeswan/libfreeswan.a
EXTRA_DIST = parser.l parser.y keywords.txt ipsec.conf
dist_man_MANS = ipsec.conf.5 starter.8
MAINTAINERCLEANFILES = lex.yy.c y.tab.c y.tab.h keywords.c

PLUTODIR=$(top_srcdir)/src/pluto
SCEPCLIENTDIR=$(top_srcdir)/src/scepclient

lex.yy.c:	y.tab.c parser.l parser.y parser.h
		$(LEX) --nounput parser.l 

y.tab.c:	parser.l parser.y parser.h
		$(YACC) -v -d parser.y

y.tab.h:	parser.l parser.y parser.h
		$(YACC) -v -d parser.y

keywords.c:	keywords.txt keywords.h
		$(GPERF) -C -G -t < keywords.txt > keywords.c

defs.o:		$(PLUTODIR)/defs.c $(PLUTODIR)/defs.h
		$(COMPILE) -c -o $@ $<

install-exec-local :	
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d"
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/cacerts" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/cacerts"
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/ocspcerts" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/ocspcerts"
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/certs" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/certs"
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/acerts" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/acerts"
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/aacerts" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/aacerts"
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/crls" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/crls"
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/reqs" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d "$(DESTDIR)$(sysconfdir)/ipsec.d/reqs"
		test -e "$(DESTDIR)${sysconfdir}/ipsec.d/private" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -d -m 750 "$(DESTDIR)$(sysconfdir)/ipsec.d/private"
		test -e "$(DESTDIR)$(sysconfdir)/ipsec.conf" || $(INSTALL) -o ${ipsecuser} -g ${ipsecgroup} -m 644 ipsec.conf $(DESTDIR)$(sysconfdir)/ipsec.conf

