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
# RCSID $Id: Makefile,v 1.2 2004/03/22 21:53:21 as Exp $

FREESWANSRCDIR=../..
include ${FREESWANSRCDIR}/Makefile.inc

PROGRAM=spi
EXTRA5PROC=${PROGRAM}.5

LIBS=${FREESWANLIB}

OBJS=constants.o alg_info.o kernel_alg.o

include ../Makefile.program

constants.o : ../pluto/constants.c ../pluto/constants.h
	$(CC) $(CFLAGS) -c -o $@ $<

alg_info.o : ../pluto/alg_info.c ../pluto/alg_info.h
	$(CC) $(CFLAGS) -DNO_PLUTO -c -o $@ $<

kernel_alg.o : ../pluto/kernel_alg.c ../pluto/kernel_alg.h
	$(CC) $(CFLAGS) -DNO_PLUTO -c -o $@ $<

#
# $Log: Makefile,v $
# Revision 1.2  2004/03/22 21:53:21  as
# merged alg-0.8.1 branch with HEAD
#
# Revision 1.1.4.1  2004/03/16 09:48:22  as
# alg-0.8.1rc12 patch merged
#
# Revision 1.1  2004/03/15 20:35:31  as
# added files from freeswan-2.04-x509-1.5.3
#
# Revision 1.4  2002/06/03 20:25:31  mcr
# 	man page for files actually existant in /proc/net changed back to
# 	ipsec_foo via new EXTRA5PROC process.
#
# Revision 1.3  2002/06/02 21:51:41  mcr
# 	changed TOPDIR->FREESWANSRCDIR in all Makefiles.
# 	(note that linux/net/ipsec/Makefile uses TOPDIR because this is the
# 	kernel sense.)
#
# Revision 1.2  2002/04/26 01:21:26  mcr
# 	while tracking down a missing (not installed) /etc/ipsec.conf,
# 	MCR has decided that it is not okay for each program subdir to have
# 	some subset (determined with -f) of possible files.
# 	Each subdir that defines $PROGRAM, MUST have a PROGRAM.8 file as well as a PROGRAM file.
# 	Optional PROGRAM.5 files have been added to the makefiles.
#
# Revision 1.1  2002/04/24 07:55:32  mcr
# 	#include patches and Makefiles for post-reorg compilation.
#
#
#
