# FreeS/WAN library
# Copyright (C) 2003	Michael Richardson	<mcr@freeswan.org>
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.1 2004/03/15 20:35:24 as Exp $


FREESWANSRCDIR=../..

include ${FREESWANSRCDIR}/Makefile.inc
include ${FREESWANSRCDIR}/Makefile.ver


MANDIR=$(MANTREE)/man3

SRCS=policyquery.c cgipolicy.c

OBJS=${SRCS:.c=.o} version.o

KLIPSD=${FREESWANSRCDIR}/linux/include

LIB=libipsecpolicy.a
# Original flags
CFLAGS=-I. -I${KLIPSD} -I${FREESWANSRCDIR} $(USERCOMPILE)
CFLAGS+= -Wall
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wcast-qual
CFLAGS+= -Wstrict-prototypes
CFLAGS+= -Wbad-function-cast 

MANS=

.PHONY:	all install clean l t lt tar check depend checkprograms

all:	$(LIB) 
programs: $(LIB)

install:
	@mkdir -p $(MANDIR)
	@for f in $(MANS) ; \
	do \
		$(INSTALL) $(INSTMANFLAGS) $(SRCDIR)/$$f $(MANDIR)/ipsec_$$f || exit 1 ; \
	done
	@$(FREESWANSRCDIR)/packaging/utils/manlink $(foreach man, $(MANS), ${SRCDIR}/$(man)) | \
	while read from to; \
	do \
		ln -s -f ipsec_$$from $(MANDIR)/$$to; \
	done


install_file_list:
	@for f in $(MANS) ; \
	do \
		echo $(MANDIR)/ipsec_$$f;\
	done;
	@$(FREESWANSRCDIR)/packaging/utils/manlink $(foreach man, $(MANS), ${SRCDIR}/$(man)) | \
	while read from to; \
	do \
		echo $(MANDIR)/$$to; \
	done

$(LIB):	$(OBJS)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

# build version.c using version number from Makefile.ver
version.c:	version.in.c ${FREESWANSRCDIR}/Makefile.ver
	sed '/"/s/xxx/$(IPSECVERSION)/' version.in.c >$@

clean:
	rm -f $(LIB) *.o try* core *.core $(EXTHDRS) $(EXTLIBS) version.c


tar:	clean
	tar -cvf /tmp/lib.tar Makefile [a-z]*

check:
	echo no checks in lib right now.

depend:
	makedepend -Y -- $(CFLAGS) -- $(SRCS)

checkprograms:

# DO NOT DELETE

