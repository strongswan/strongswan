# (kernel) Makefile for IPCOMP zlib deflate code
# Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
# Copyright (C) 2000  Svenning Soerensen
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
# RCSID $Id: Makefile,v 1.1 2004/03/15 20:35:26 as Exp $
#



include ../Makefile.inc



ifndef TOPDIR
TOPDIR  := /usr/src/linux
endif


L_TARGET := zlib.a

obj-y :=

include Makefile.objs

EXTRA_CFLAGS += $(KLIPSCOMPILE)

EXTRA_CFLAGS += -Wall 
#EXTRA_CFLAGS += -Wconversion 
#EXTRA_CFLAGS += -Wmissing-prototypes 
EXTRA_CFLAGS += -Wpointer-arith 
#EXTRA_CFLAGS += -Wcast-qual 
#EXTRA_CFLAGS += -Wmissing-declarations 
EXTRA_CFLAGS += -Wstrict-prototypes
#EXTRA_CFLAGS += -pedantic
#EXTRA_CFLAGS += -W
#EXTRA_CFLAGS += -Wwrite-strings 
EXTRA_CFLAGS += -Wbad-function-cast 
EXTRA_CFLAGS += -DIPCOMP_PREFIX

.S.o:
	$(CC) -D__ASSEMBLY__ -DNO_UNDERLINE -traditional -c $< -o $*.o

asm-obj-$(CONFIG_M586)		+= match586.o
asm-obj-$(CONFIG_M586TSC)	+= match586.o
asm-obj-$(CONFIG_M586MMX)	+= match586.o
asm-obj-$(CONFIG_M686)		+= match686.o
asm-obj-$(CONFIG_MPENTIUMIII)	+= match686.o
asm-obj-$(CONFIG_MPENTIUM4)	+= match686.o
asm-obj-$(CONFIG_MK6)		+= match586.o
asm-obj-$(CONFIG_MK7)		+= match686.o
asm-obj-$(CONFIG_MCRUSOE)	+= match586.o
asm-obj-$(CONFIG_MWINCHIPC6)	+= match586.o
asm-obj-$(CONFIG_MWINCHIP2)	+= match686.o
asm-obj-$(CONFIG_MWINCHIP3D)	+= match686.o

obj-y += $(asm-obj-y)
ifneq ($(strip $(asm-obj-y)),)
  EXTRA_CFLAGS += -DASMV
endif

active-objs     := $(sort $(obj-y) $(obj-m))
L_OBJS          := $(obj-y)
M_OBJS          := $(obj-m)
MIX_OBJS        := $(filter $(export-objs), $(active-objs))

include $(TOPDIR)/Rules.make

$(obj-y) :  $(TOPDIR)/include/linux/config.h $(TOPDIR)/include/linux/autoconf.h


clean:
	-rm -f *.o *.a

checkprograms:
programs: $(L_TARGET)

#
# $Log: Makefile,v $
# Revision 1.1  2004/03/15 20:35:26  as
# added files from freeswan-2.04-x509-1.5.3
#
# Revision 1.9  2002/04/24 07:55:32  mcr
# 	#include patches and Makefiles for post-reorg compilation.
#
# Revision 1.8  2002/04/24 07:36:44  mcr
# Moved from ./zlib/Makefile,v
#
# Revision 1.7  2002/03/27 23:34:35  mcr
# 	added programs: target
#
# Revision 1.6  2001/12/05 20:19:08  henry
# use new compile-control variable
#
# Revision 1.5  2001/11/27 16:38:08  mcr
# 	added new "checkprograms" target to deal with programs that
# 	are required for "make check", but that may not be ready to
# 	build for every user due to external dependancies.
#
# Revision 1.4  2001/10/24 14:46:24  henry
# Makefile.inc
#
# Revision 1.3  2001/04/21 23:05:24  rgb
# Update asm directives for 2.4 style makefiles.
#
# Revision 1.2  2001/01/29 22:22:00  rgb
# Convert to 2.4 new style with back compat.
#
# Revision 1.1.1.1  2000/09/29 18:51:33  rgb
# zlib_beginnings
#
#
