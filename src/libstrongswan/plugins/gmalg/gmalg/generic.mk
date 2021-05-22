
IDIR            += ./include
IDIR            += ./private_include

CFLAGS          := $(addprefix -I, $(IDIR))
CFLAGS          += $(addprefix -L, $(LDIR))
CFLAGS          += $(addprefix -D, $(DEFS))
CFLAGS          += -shared -fPIC -Werror -O3

export IDIR LDIR DEFS
