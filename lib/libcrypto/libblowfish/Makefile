#
# SSLeay/crypto/blowfish/Makefile
#

DIR=	bf
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INC=-I ../include 
CFLAG=-g -D__KERNEL__ -I/usr/src/linux/include
INSTALL_PREFIX=
OPENSSLDIR=     /usr/local/ssl
INSTALLTOP=/usr/local/ssl
MAKE=		make -f Makefile.ssl
MAKEDEPEND=	$(TOP)/util/domd $(TOP)
MAKEFILE=	Makefile.ssl
AR=		ar r
RANLIB=		ranlib
PERL=		perl

CFLAGS= $(INC) $(CFLAG)

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -c $< -o $@

BF_ASM-i586 := bf-586.pl
BF_ASM-i686 := bf-686.pl
BF_ENC := bf_enc.o

ASM-$(ARCH_ASM):=1
ASM_X86:=$(ASM-i586)$(ASM-i686)
ifneq ($(strip $(ASM_X86)),)
	BF_ENC=	asm/bx86-elf.o
	BF_ASM= $(BF_ASM-$(ARCH_ASM))
endif


GENERAL=Makefile
TEST=bftest.c
APPS=

LIB=libblowfish.a
LIBSRC=bf_skey.c bf_enc.c 
LIBOBJ=bf_skey.o $(BF_ENC)

SRC= $(LIBSRC)

EXHEADER= blowfish.h
HEADER=	bf_pi.h bf_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

#top:
#	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIB)

$(LIB):	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB)

# elf
asm/bx86-elf.o: asm/bx86unix.cpp
	$(CPP) -DELF -x c asm/bx86unix.cpp | as -o asm/bx86-elf.o

# solaris
asm/bx86-sol.o: asm/bx86unix.cpp
	$(CC) -E -DSOL asm/bx86unix.cpp | sed 's/^#.*//' > asm/bx86-sol.s
	as -o asm/bx86-sol.o asm/bx86-sol.s
	rm -f asm/bx86-sol.s

# a.out
asm/bx86-out.o: asm/bx86unix.cpp
	$(CPP) -DOUT asm/bx86unix.cpp | as -o asm/bx86-out.o

# bsdi
asm/bx86bsdi.o: asm/bx86unix.cpp
	$(CPP) -DBSDI asm/bx86unix.cpp | sed 's/ :/:/' | as -o asm/bx86bsdi.o

asm/bx86unix.cpp: asm/$(BF_ASM) ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm; $(PERL) $(BF_ASM) cpp $(PROCESSOR) >bx86unix.cpp)

files:
	$(PERL) $(TOP)/util/files.pl Makefile.ssl >> $(TOP)/MINFO

links:
	@$(TOP)/util/point.sh Makefile.ssl Makefile
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install: installs

installs:
	@for i in $(EXHEADER) ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	$(MAKEDEPEND) $(INCLUDES) $(DEPFLAG) $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f asm/bx86unix.cpp *.o asm/*.o *.obj $(LIB) tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.
