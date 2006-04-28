# Makefile for the KLIPS interface utilities
# Copyright (C) 2003	Michael Richardson <mcr@freeswan.org>
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
# RCSID $Id: Makefile,v 1.1 2004/03/15 20:35:31 as Exp $

FREESWANSRCDIR=../..
include ${FREESWANSRCDIR}/Makefile.inc

PROGRAM=showpolicy
EXTRA5PROC=${PROGRAM}.8

LIBS=${POLICYLIB} ${FREESWANLIB} 

include ../Makefile.program

#
# $Log: Makefile,v $
# Revision 1.1  2004/03/15 20:35:31  as
# added files from freeswan-2.04-x509-1.5.3
#
# Revision 1.2  2003/05/14 02:12:27  mcr
# 	addition of CGI-focused interface to policy lookup interface
#
# Revision 1.1  2003/05/11 00:45:08  mcr
# 	program to interogate ipsec policy of stdin.
# 	run this from inetd.
#
#
