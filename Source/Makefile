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
else
  # use leak detective by default
  USE_LEAK_DETECTIVE?=true
endif




BUILD_DIR= ./bin/

BINNAMECHARON= $(BUILD_DIR)charon
BINNAMESTROKE= $(BUILD_DIR)stroke
BINNAMETEST= $(BUILD_DIR)run_tests
BINNAMELIB=  $(BUILD_DIR)libstrongswan.so

MAIN_DIR= ./

CFLAGS= -Icharon -Ilib -Istroke -fPIC -Wall -g
ifeq ($(USE_LEAK_DETECTIVE),true)
  CFLAGS+= -DLEAK_DETECTIVE
endif

# objects is extended by each included Makefile
CHARON_OBJS=
LIB_OBJS=
TEST_OBJS=

all :						programs

include $(MAIN_DIR)charon/Makefile.charon
include $(MAIN_DIR)lib/Makefile.lib
include $(MAIN_DIR)stroke/Makefile.stroke
include $(MAIN_DIR)testing/Makefile.testcases

programs : 					$(BINNAMECHARON) $(BINNAMESTROKE)

test :						$(BINNAMETEST)
							LD_LIBRARY_PATH=$(BUILD_DIR) $(BINNAMETEST)

run :						$(BINNAMECHARON)
							LD_LIBRARY_PATH=$(BUILD_DIR) $(BINNAMECHARON)

apidoc : 
							doxygen Doxyfile

build_dir:
							mkdir -p $(BUILD_DIR)
							
$(BINNAMELIB) :				build_dir $(LIB_OBJS)
							$(CC) -ldl -lgmp -lpthread -shared $(LIB_OBJS) -o $@

$(BINNAMECHARON) :			build_dir $(CHARON_OBJS) $(BINNAMELIB) $(BUILD_DIR)daemon.o
							$(CC) -L./bin -lstrongswan $(CHARON_OBJS) $(BUILD_DIR)daemon.o -o $@

$(BINNAMETEST) :			build_dir $(CHARON_OBJS) $(TEST_OBJS) $(BINNAMELIB) $(BUILD_DIR)testcases.o
							$(CC) -L./bin -lstrongswan  $(LDFLAGS) $(CHARON_OBJS) $(TEST_OBJS) $(BUILD_DIR)testcases.o -o $@

$(BINNAMESTROKE) :			build_dir $(BINNAMELIB) $(BUILD_DIR)stroke.o
							$(CC) $(LDFLAGS) $(CFLAGS) $(BUILD_DIR)stroke.o -o $@

install :					$(BINNAMECHARON) $(BINNAMESTROKE)
							$(INSTALL) $(INSTBINFLAGS) $(BINNAMECHARON) $(BINNAMESTROKE) $(LIBEXECDIR)
							$(INSTALL) $(INSTBINFLAGS) $(BINNAMELIB) $(SHAREDLIBDIR)
				
install_file_list:
							@echo $(LIBEXECDIR)/charon
							@echo $(LIBEXECDIR)/stroke
							@echo $(SHAREDLIBDIR)/libstrongswan.so

clean : 		
							rm -fR $(BUILD_DIR)
				
cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean
