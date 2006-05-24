ipsec_PROGRAMS = starter
starter_SOURCES = y.tab.c netkey.c y.tab.h parser.h args.h netkey.h \
starterwhack.c starterwhack.h starterstroke.c invokepluto.c confread.c \
starterstroke.h interfaces.c invokepluto.h confread.h  interfaces.h args.c \
keywords.c files.h keywords.h cmp.c starter.c cmp.h exec.c invokecharon.c \
exec.h invokecharon.h lex.yy.c

INCLUDES = -I$(top_srcdir)/src/libfreeswan -I$(top_srcdir)/src/pluto -I$(top_srcdir)/src/whack -I$(top_srcdir)/src/stroke
AM_CFLAGS = -DIPSEC_DIR=\"${ipsecdir}\" -DIPSEC_CONFDIR=\"${confdir}\" -DIPSEC_PIDDIR=\"${piddir}\" -DDEBUG
starter_LDADD = loglite.o defs.o $(top_srcdir)/src/libfreeswan/libfreeswan.a
EXTRA_DIST = parser.l parser.y keywords.txt ipsec.conf
dist_man_MANS = ipsec.conf.5
MAINTAINERCLEANFILES = lex.yy.c y.tab.c y.tab.h keywords.c

PLUTODIR=$(top_srcdir)/src/pluto
OPENACDIR=$(top_srcdir)/src/openac

lex.yy.c:	y.tab.c parser.l parser.y parser.h
		$(LEX) parser.l

y.tab.c:	parser.l parser.y parser.h
		$(YACC) -v -d parser.y

y.tab.h:	parser.l parser.y parser.h
		$(YACC) -v -d parser.y

keywords.c:	keywords.txt keywords.h
		$(GPERF) -C -G -t < keywords.txt > keywords.c

loglite.o:	$(OPENACDIR)/loglite.c $(PLUTODIR)/log.h
		$(CC) $(AM_CFLAGS) $(INCLUDES) -c -o $@ $<

defs.o:		$(PLUTODIR)/defs.c $(PLUTODIR)/defs.h
		$(CC) $(AM_CFLAGS) $(INCLUDES) -c -o $@ $<

install-exec-local :
		test -e "$(sysconfdir)/ipsec.conf" || $(INSTALL) ipsec.conf $(sysconfdir)/ipsec.conf
