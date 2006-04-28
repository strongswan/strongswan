# Copyright (C) 2000, 2001  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: Makefile,v 1.1 2004/03/15 20:35:25 as Exp $

srcdir =	.
VPATH =		.
top_srcdir =	.

CINCLUDES =	-I${srcdir}/unix/include \
		-I. -I./include -I${srcdir}/include 
CDEFINES = -g
CWARNINGS = -Werror

CFLAGS=${CINCLUDES} ${CDEFINES} ${CWARNINGS}

VERSION="@(\#) freeswan-hacking-9.2.1-for-fs2"
LIBINTERFACE=2
LIBREVISION=0
LIBAGE=1
RANLIB=ranlib

# Alphabetically
OBJS =		async.o context.o gai_strerror.o getaddrinfo.o gethost.o \
		getipnode.o getnameinfo.o getrrset.o getrrset2.o herror.o \
		lwbuffer.o lwconfig.o lwpacket.o lwresutil.o \
		lwres_gabn.o lwres_gnba.o lwres_grbn.o lwres_noop.o \
		lwinetaton.o lwinetpton.o lwinetntop.o

# Alphabetically
SRCS =		async.c context.c gai_strerror.c getaddrinfo.c gethost.c \
		getipnode.c getnameinfo.c getrrset.c getrrset2.c herror.c \
		lwbuffer.c lwconfig.c lwpacket.c lwresutil.c \
		lwres_gabn.c lwres_gnba.c lwres_grbn.c lwres_noop.c \
		lwinetaton.c lwinetpton.c lwinetntop.c

programs all: liblwres.a

version.o: version.c
	${LIBTOOL} ${CC} ${ALL_CFLAGS} \
		-DVERSION=\"${VERSION}\" \
		-DLIBINTERFACE=${LIBINTERFACE} \
		-DLIBREVISION=${LIBREVISION} \
		-DLIBAGE=${LIBAGE} \
		-c ${srcdir}/version.c

liblwres.a: ${OBJS} version.o
	${AR} ${ARFLAGS} $@ ${OBJS} version.o
	${RANLIB} $@

timestamp: liblwres.a
	touch timestamp

clean distclean mostlyclean realclean cleanall spotless::
	rm -f liblwres.a liblwres.la timestamp $(OBJS)

install checkprograms check install_file_list:
	@true

TAGS: ${SRCS}
	etags ${SRCS}
