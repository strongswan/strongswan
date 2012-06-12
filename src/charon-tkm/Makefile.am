SRC = $(top_builddir)/src

# includes relative to obj directory
INCLUDES = \
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
	-cargs $(INCLUDES) $(DEFS) \
	-largs $(LIBLD) $(LIBFL)

# plugins to enable
PLUGINS = \
	aes \
	constraints \
	gmp \
	hmac \
	kernel-netlink \
	pem \
	pkcs1 \
	pkcs8 \
	random \
	sha1 \
	sha2 \
	stroke \
	socket-default \
	x509

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
