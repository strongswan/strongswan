# Copyright (C) 2005 Jan Hutter, Martin Willi
# Hochschule fuer Technik Rapperswil
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

FREESWANSRCDIR=../..
# include strongswan Makefile, if charon sits in its tree
ifeq ($(shell ls $(FREESWANSRCDIR)/Makefile.inc 2>&1), ../../Makefile.inc)
  include ${FREESWANSRCDIR}/Makefile.inc
endif

BUILD_DIR= ./bin/

BINNAMECHARON= $(BUILD_DIR)charon
BINNAMESTROKE= $(BUILD_DIR)stroke
BINNAMETEST= $(BUILD_DIR)run_tests

MAIN_DIR= ./

LDFLAGS= -lgmp -lpthread

CFLAGS+= -I. -O3#-Wall -g -DLEAK_DETECTIVE 

# objects is extended by each included Makefile
OBJS= 

all : 			build_dir $(BINNAMECHARON) $(BINNAMESTROKE)

programs :		all

test :			build_dir $(BINNAMETEST)
			$(BINNAMETEST)

apidoc : 
			doxygen Doxyfile


include $(MAIN_DIR)network/Makefile.network
include $(MAIN_DIR)config/Makefile.config
include $(MAIN_DIR)encoding/Makefile.encoding
include $(MAIN_DIR)queues/Makefile.queues
include $(MAIN_DIR)sa/Makefile.sa
include $(MAIN_DIR)threads/Makefile.threads
include $(MAIN_DIR)transforms/Makefile.transforms
include $(MAIN_DIR)utils/Makefile.utils	
include $(MAIN_DIR)asn1/Makefile.asn1	


build_dir:
				mkdir -p $(BUILD_DIR)

$(BUILD_DIR)daemon.o :		daemon.c daemon.h 
				$(CC) $(CFLAGS) -c -o $@ $<

OBJS+=$(BUILD_DIR)types.o
$(BUILD_DIR)types.o :		types.c types.h
				$(CC) $(CFLAGS) -c -o $@ $<

OBJS+=$(BUILD_DIR)definitions.o
$(BUILD_DIR)definitions.o :	definitions.c definitions.h
				$(CC) $(CFLAGS) -c -o $@ $<

$(BINNAMECHARON) :		$(OBJS) $(BUILD_DIR)daemon.o
				$(CC) $(LDFLAGS) $(OBJS) $(BUILD_DIR)daemon.o -o $@

$(BINNAMESTROKE) :		stroke.c
				$(CC) $(LDFLAGS) $(CFLAGS) stroke.c -o $@

TEST_OBJS = $(OBJS)
include $(MAIN_DIR)testcases/Makefile.testcases	

$(BUILD_DIR)run_tests :		build_dir $(TEST_OBJS)
				$(CC) $(LDFLAGS) $(TEST_OBJS) -o $@

install :			$(BINNAMECHARON)
				$(INSTALL) $(INSTBINFLAGS) $(BINNAMECHARON) $(BINNAMESTROKE) $(LIBEXECDIR)
				
install_file_list:
				@echo $(LIBEXECDIR)/charon
				@echo $(LIBEXECDIR)/stroke

clean : 		
				rm -fR $(BUILD_DIR); rm -Rf doc/api
				
cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean
