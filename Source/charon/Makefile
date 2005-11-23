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

BUILD_DIR= ./bin/

MAIN_DIR= ./

LIBS= -lgmp -lpthread

CFLAGS+= -DLEAK_DETECTIVE -I.

# objects is extended by each included Makefile
OBJS= 

daemon :		build_dir $(BUILD_DIR)charon

all :		build_dir $(BUILD_DIR)charon $(BUILD_DIR)run_tests

doxygen : 
			doxygen doxyconfig.DoxyFile

include $(MAIN_DIR)network/Makefile.network
include $(MAIN_DIR)config/Makefile.config
include $(MAIN_DIR)encoding/Makefile.encoding
include $(MAIN_DIR)queues/Makefile.queues
include $(MAIN_DIR)sa/Makefile.sa

build_dir:
							mkdir $(BUILD_DIR)

$(BUILD_DIR)daemon.o :		daemon.c daemon.h 
							$(CC) $(CFLAGS) -c -o $@ $<

OBJS+=$(BUILD_DIR)types.o
$(BUILD_DIR)types.o :		types.c types.h
							$(CC) $(CFLAGS) -c -o $@ $<

OBJS+=$(BUILD_DIR)definitions.o
$(BUILD_DIR)definitions.o :	definitions.c definitions.h
							$(CC) $(CFLAGS) -c -o $@ $<



$(BUILD_DIR)charon :		$(OBJS) $(BUILD_DIR)daemon.o
							$(CC) $(CFLAGS) $(OBJS) $(BUILD_DIR)daemon.o -o $@ 
				
							
#include testcases/Makefile.testcases	
				
#$(BUILD_DIR)run_tests :		$(OBJS)
							$(CC) $(CFLAGS) $(OBJS) -o $@ 
				

clean : 		
							rm $(OBJS) $(BUILD_DIR)charon $(BUILD_DIR)daemon.o; \
							rmdir $(BUILD_DIR)