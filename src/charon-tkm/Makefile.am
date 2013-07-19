SRC = $(top_builddir)/src

# includes relative to obj directory
AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I../$(SRC)/libstrongswan \
	-I../$(SRC)/libhydra \
	-I../$(SRC)/libcharon

LIBLD = \
	-L$(SRC)/libstrongswan/.libs \
	-L$(SRC)/libhydra/.libs \
	-L$(SRC)/libcharon/.libs
LIBPT = $(SRC)/libstrongswan/.libs:$(SRC)/libhydra/.libs:$(SRC)/libcharon/.libs
LIBFL = -lstrongswan -lhydra -lcharon

DEFS += -DPLUGINS=\""$(PLUGINS)\"" -DIPSEC_PIDDIR=\"${piddir}\"

BUILD_OPTS = \
	-XOBJ_DIR=$(CURDIR)/obj \
	-cargs $(AM_CPPFLAGS) $(DEFS) \
	-largs $(LIBLD) $(LIBFL)

# plugins to enable
PLUGINS = \
	kernel-netlink \
	pem \
	socket-default \
	openssl \
	stroke

all: build_charon

build_charon: build_charon.gpr src/charon-tkm.c
	@$(GPRBUILD) -p $< $(BUILD_OPTS)

build_tests: build_tests.gpr
	@$(GPRBUILD) -p $< $(BUILD_OPTS) -cargs @CHECK_CFLAGS@ -largs @CHECK_LIBS@

if UNITTESTS
check: build_tests
	@LD_LIBRARY_PATH=$(LIBPT) obj/test_runner
else
check:
	@echo "reconfigure with --enable-unit-tests"
endif

install: build_charon
	$(INSTALL) -m 755 obj/charon-tkm $(DESTDIR)$(ipsecdir)

clean:
	rm -rf obj

EXTRA_DIST = build_charon.gpr build_common.gpr build_tests.gpr src tests
