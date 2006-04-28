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
# RCSID $Id: Makefile,v 1.1 2004/03/15 20:35:27 as Exp $

FREESWANSRCDIR=../..
include ${FREESWANSRCDIR}/Makefile.inc

PROGRAM=ikeping
LIBS=${FREESWANLIB}

ifeq ($(USE_IKEPING),false)
NOINSTALL=true
install:
	# do nothing

install_file_list:
	# do nothing

endif

include ../Makefile.program

#
# $Log: Makefile,v $
# Revision 1.1  2004/03/15 20:35:27  as
# added files from freeswan-2.04-x509-1.5.3
#
# Revision 1.4  2003/06/29 21:34:49  mcr
# 	added "NOINSTALL" to omit install: target from common
# 	Makefile so that it can be overridden
#
# Revision 1.3  2003/06/25 03:57:45  mcr
# 	build, but do not install "ikeping" even when we do not
# 	want it as part of the system.
#
# Revision 1.2  2002/06/02 22:02:14  mcr
# 	changed TOPDIR->FREESWANSRCDIR in all Makefiles.
# 	(note that linux/net/ipsec/Makefile uses TOPDIR because this is the
# 	kernel sense.)
#
# Revision 1.1  2002/04/24 07:55:32  mcr
# 	#include patches and Makefiles for post-reorg compilation.
#
#
#
