# FreeS/WAN master makefile
# Copyright (C) 1998-2002  Henry Spencer.
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
# RCSID $Id: Makefile,v 1.4 2004/11/14 21:50:59 as Exp $


FREESWANSRCDIR=$(shell pwd)
export FREESWANSRCDIR

include Makefile.inc

# directories visited by all recursion
SUBDIRS=lib programs linux

# declaration for make's benefit
.PHONY:	programs install clean distclean \
	uninstall install_file_list

# programs

all:	programs

programs install install_file_list clean::
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) FREESWANSRCDIR=.. $@ ) || exit 1; \
	done; \

# uninstall, as much as possible
uninstall:
	$(MAKE) --no-print-directory install_file_list | egrep -v '(/ipsec.conf$$|/ipsec.d/)' | xargs rm -f

