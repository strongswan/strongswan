AM_CPPFLAGS = @CPPFLAGS@ \
	-I$(top_srcdir)/src/libstrongswan \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS="\"${fuzz_plugins}\""

fuzz_ldflags = ${libfuzzer} \
	$(top_builddir)/src/libstrongswan/.libs/libstrongswan.a \
	-Wl,-Bstatic -lgmp -Wl,-Bdynamic \
	@FUZZING_LDFLAGS@

FUZZ_TARGETS=fuzz_certs

all-local: $(FUZZ_TARGETS)

CLEANFILES=$(FUZZ_TARGETS)

fuzz_certs: fuzz_certs.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

noinst_LIBRARIES = libFuzzerLocal.a
libFuzzerLocal_a_SOURCES = libFuzzerLocal.c
libFuzzerLocal_a_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

check: all
	for f in $(FUZZ_TARGETS); do \
		corpus=$${f#fuzz_}; \
		corpus=$${corpus%%_*}; \
		./$$f $(FUZZING_CORPORA)/$${corpus}/*; \
		crashes=$(FUZZING_CORPORA)/$${corpus}-crash; \
		test ! -d $${crashes} || ./$$f $${crashes}/*; \
	done
