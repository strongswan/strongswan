AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) \
	@COVERAGE_CFLAGS@

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-bliss.la
else
plugin_LTLIBRARIES = libstrongswan-bliss.la
endif

libstrongswan_bliss_la_SOURCES = \
	bliss_plugin.h bliss_plugin.c \
	bliss_param_set.h bliss_param_set.c \
	bliss_private_key.h bliss_private_key.c \
	bliss_public_key.h bliss_public_key.c \
	bliss_signature.h bliss_signature.c \
	bliss_utils.h bliss_utils.c \
	bliss_bitpacker.h bliss_bitpacker.c \
	bliss_fft.h bliss_fft.c \
	bliss_fft_params.h bliss_fft_params.c \
	bliss_huffman_code.h bliss_huffman_code.c \
	bliss_huffman_code_1.c bliss_huffman_code_3.c bliss_huffman_code_4.c \
	bliss_sampler.h bliss_sampler.c

libstrongswan_bliss_la_LDFLAGS = -module -avoid-version

noinst_PROGRAMS = bliss_huffman

bliss_huffman_SOURCES = bliss_huffman.c
bliss_huffman_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la -lm \
	bliss_param_set.o bliss_fft_params.o

bliss_huffman_code_1.c :	bliss_huffman bliss_huffman_code.h
	$(AM_V_GEN) \
	./bliss_huffman 1 8 > $@

bliss_huffman_code_3.c :	bliss_huffman bliss_huffman_code.h
	$(AM_V_GEN) \
	./bliss_huffman 3 16 > $@

bliss_huffman_code_4.c :	bliss_huffman bliss_huffman_code.h
	$(AM_V_GEN) \
	./bliss_huffman 4 32 > $@

TESTS = bliss_tests

check_PROGRAMS = $(TESTS)

bliss_tests_SOURCES = \
	suites/test_bliss_fft.c \
	suites/test_bliss_bitpacker.c \
	suites/test_bliss_sampler.c \
	suites/test_bliss_sign.c \
	bliss_fft_params.c \
	bliss_fft.c \
	bliss_private_key.c \
	bliss_public_key.c \
	bliss_param_set.c \
	bliss_sampler.c \
	bliss_signature.c \
	bliss_utils.c \
	bliss_bitpacker.c \
	bliss_tests.h bliss_tests.c

bliss_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS=\""${s_plugins}\"" \
	@COVERAGE_CFLAGS@

bliss_tests_LDFLAGS = @COVERAGE_LDFLAGS@
bliss_tests_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la
