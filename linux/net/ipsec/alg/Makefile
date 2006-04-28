# $Id: Makefile,v 1.2 2004/03/22 21:53:19 as Exp $
ifeq ($(strip $(KLIPSMODULE)),)
FREESWANSRCDIR=.
else
FREESWANSRCDIR=../../../..
endif
ifeq ($(strip $(KLIPS_TOP)),)
KLIPS_TOP=../../..
override EXTRA_CFLAGS += -I$(KLIPS_TOP)/include
endif

ifeq ($(CONFIG_IPSEC_DEBUG),y)
override EXTRA_CFLAGS += -g
endif

# LIBCRYPTO normally comes as an argument from "parent" Makefile
# (this applies both to FS' "make module" and eg. Linux' "make modules"
# But make dep doest follow same evaluations, so we need this default:
LIBCRYPTO=$(TOPDIR)/lib/libcrypto

override EXTRA_CFLAGS += -I$(LIBCRYPTO)/include
override EXTRA_CFLAGS += -Wall -Wpointer-arith -Wstrict-prototypes

MOD_LIST_NAME := NET_MISC_MODULES

#O_TARGET := static_init.o

subdir-  := 
subdir-n := 
subdir-y :=
subdir-m :=

obj-y := static_init.o

ARCH_ASM-y :=
ARCH_ASM-$(CONFIG_M586)		:= i586
ARCH_ASM-$(CONFIG_M586TSC)	:= i586
ARCH_ASM-$(CONFIG_M586MMX)	:= i586
ARCH_ASM-$(CONFIG_MK6)		:= i586
ARCH_ASM-$(CONFIG_M686)		:= i686
ARCH_ASM-$(CONFIG_MPENTIUMIII)	:= i686
ARCH_ASM-$(CONFIG_MPENTIUM4)	:= i686
ARCH_ASM-$(CONFIG_MK7)		:= i686
ARCH_ASM-$(CONFIG_MCRUSOE)	:= i586
ARCH_ASM-$(CONFIG_MWINCHIPC6)	:= i586
ARCH_ASM-$(CONFIG_MWINCHIP2)	:= i586
ARCH_ASM-$(CONFIG_MWINCHIP3D)	:= i586
ARCH_ASM-$(CONFIG_USERMODE)	:= i586

ARCH_ASM :=$(ARCH_ASM-y)
ifdef NO_ASM
ARCH_ASM :=
endif

# The algorithm makefiles may put dependences, short-circuit them
null:

makefiles=$(filter-out %.preipsec, $(wildcard Makefile.alg_*))
ifneq ($(makefiles),)
#include Makefile.alg_aes
#include Makefile.alg_aes-opt
include $(makefiles)
endif

# These rules translate from new to old makefile rules
# Translate to Rules.make lists.
multi-used      := $(filter $(list-multi), $(obj-y) $(obj-m))
multi-objs      := $(foreach m, $(multi-used), $($(basename $(m))-objs))
active-objs     := $(sort $(multi-objs) $(obj-y) $(obj-m))
O_OBJS          := $(obj-y)
M_OBJS          := $(obj-m)
MIX_OBJS        := $(filter $(export-objs), $(active-objs))
#OX_OBJS := $(export-objs)
SUB_DIRS := $(subdir-y)
ALL_SUB_DIRS := $(subdir-y) $(subdir-m)
MOD_SUB_DIRS := $(subdir-m)


static_init_mod.o: $(obj-y) 
	rm -f $@
	$(LD) $(LD_EXTRAFLAGS) $(obj-y) -r -o $@

perlasm: $(LIBCRYPTO)/perlasm
	ln -sf $? $@

$(obj-y) $(obj-m): $(TOPDIR)/include/linux/config.h $(TOPDIR)/include/linux/autoconf.h $(KLIPS_TOP)/include/freeswan/ipsec_alg.h
$(alg_obj-y) $(alg_obj-m): perlasm $(TOPDIR)/include/linux/config.h $(TOPDIR)/include/linux/autoconf.h $(KLIPS_TOP)/include/freeswan/ipsec_alg.h


all_alg_modules: perlasm $(ALG_MODULES)
	@echo "ALG_MODULES=$(ALG_MODULES)"


#
# Construct alg. init. function: call ipsec_ALGO_init() for every static algo
# Needed when there are static algos (with static or modular ipsec.o)
#
static_init.c: $(TOPDIR)/include/linux/autoconf.h Makefile $(makefiles) scripts/mk-static_init.c.sh
	@echo "Re-creating $@"
	$(SHELL) scripts/mk-static_init.c.sh $(static_init-func-y) > $@

clean:
	@for i in $(ALG_SUBDIRS);do test -d $$i && make -C $$i clean;done;exit 0
	@find . -type l  -exec rm -f {} \;
	-rm -f perlasm
	-rm -rf $(ALG_SUBDIRS)
	-rm -f *.o .*.o.flags static_init.c

ifdef TOPDIR
include $(TOPDIR)/Rules.make
endif

