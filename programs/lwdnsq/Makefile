# Makefile for the KLIPS interface utilities
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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
# RCSID $Id: Makefile,v 1.1 2004/03/15 20:35:28 as Exp $

FREESWANSRCDIR=../..
include ${FREESWANSRCDIR}/Makefile.inc

PROGRAM:=lwdnsq

OBJS:=cmds.o lookup.o

LWRESINCL=${LWRESDIR}/include

LIBS:=${FREESWANLIB} ${LWRESLIB} ${BIND9STATICLIBDIR}/libdns.a ${BIND9STATICLIBDIR}/libisc.a
CFLAGS+=-I${LWRESINCL}
#USERCOMPILE=-g


include ../Makefile.program

lwdnsq.8: lwdnsq.xml
	xmlto man lwdnsq.xml

lwdnsq.xml: lwdnsq.xml.in

TAGS: 
	etags *.[ch] ../../lib/liblwres/*.[ch] ../../lib/liblwres/include/lwres/*.h

# manually maintained dependancies
lwdnsq.o:	lwdnsq.c lwdnsq.h 
cmds.o:		cmds.c lwdnsq.h
lookup.o:	lookup.c lwdnsq.h


#
# $Log: Makefile,v $
# Revision 1.1  2004/03/15 20:35:28  as
# added files from freeswan-2.04-x509-1.5.3
#
# Revision 1.9  2003/09/03 01:13:24  mcr
# 	first attempt at async capable lwdnsq.
#
# Revision 1.8  2003/02/27 09:29:02  mcr
# 	moved targets to after include file so that XML-conversion
# 	does not occur by default.
#
# Revision 1.7  2003/02/01 01:36:53  mcr
#    updates to lwdnsq man page to reflect CONTRACT
#
# Revision 1.6  2003/01/14 03:01:14  dhr
#
# improve diagnostics; tidy
#
# Revision 1.5  2003/01/10 23:20:40  dhr
#
# remove reference to /sandel
#
# Revision 1.4  2002/12/19 05:45:47  mcr
# 	use BIND9STATICLIBDIR to find -lisc/-ldns.
#
# Revision 1.3  2002/12/12 06:03:41  mcr
# 	added --regress option to force times to be regular
#
# Revision 1.2  2002/12/04 03:21:06  mcr
# 	DNS zone files (with signed versions) for DNSSEC enabled testing root.
#
# Revision 1.1  2002/10/30 02:25:31  mcr
# 	renamed version of files from dnskey/
#
# Revision 1.4  2002/10/18 04:08:02  mcr
# 	added -ldns and -lisc to libraries, but it isn't clear
# 	where we will find these only-slightly standard libraries yet.
#
# Revision 1.3  2002/10/09 20:13:10  mcr
# 	get appropriate LWRES include directory.
#
# Revision 1.2  2002/09/30 18:55:54  mcr
# 	skeleton for dnskey helper program.
#
# Revision 1.1  2002/09/30 16:50:23  mcr
# 	documentation for "dnskey" helper
#
#
#
