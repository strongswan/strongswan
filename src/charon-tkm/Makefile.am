SRC = $(abs_top_srcdir)/src
OBJ = $(abs_top_builddir)/src

AM_CPPFLAGS = \
	-include $(abs_top_builddir)/config.h \
	-I$(SRC)/libstrongswan \
	-I$(SRC)/libhydra \
	-I$(SRC)/libcharon

LIBLD = \
	-L$(OBJ)/libstrongswan/.libs \
	-L$(OBJ)/libhydra/.libs \
	-L$(OBJ)/libcharon/.libs
LIBPT = $(OBJ)/libstrongswan/.libs:$(OBJ)/libhydra/.libs:$(OBJ)/libcharon/.libs
LIBFL = -lstrongswan -lhydra -lcharon

DEFS += -DPLUGINS=\""$(PLUGINS)\"" -DIPSEC_PIDDIR=\"${piddir}\"

BUILD_OPTS = \
	-XOBJ_DIR=$(abs_builddir)/obj \
	-cargs $(AM_CPPFLAGS) $(DEFS) \
	-largs $(LIBLD) $(LIBFL)

TEST_OPTS = \
	-cargs -DBUILDDIR=\"${abs_top_builddir}\" \
	-largs -L$(OBJ)/libstrongswan/tests/.libs -ltest

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
	@$(GPRBUILD) -p $< $(BUILD_OPTS) $(TEST_OPTS)

if UNITTESTS
check: build_tests
	@LD_LIBRARY_PATH=$(LIBPT) obj/tests
else
check:
	@echo "reconfigure with --enable-unit-tests"
endif

install: build_charon
	$(INSTALL) -m 755 obj/charon-tkm $(DESTDIR)$(ipsecdir)

clean:
	rm -rf obj

EXTRA_DIST = build_charon.gpr build_common.gpr build_tests.gpr src tests
