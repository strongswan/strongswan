CPPFLAGS = @CPPFLAGS@ \
	-I$(top_srcdir)/src/libstrongswan \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS="\"${fuzz_plugins}\""

LDFLAGS = @LDFLAGS@ ${libfuzzer} \
	$(top_builddir)/src/libstrongswan/.libs/libstrongswan.a \
	-Wl,-Bstatic -lgmp -Wl,-Bdynamic \
	-stdlib=libc++ -lstdc++

FUZZ_TARGETS=fuzz_certs

all-local: $(FUZZ_TARGETS)

CLEANFILES=$(FUZZ_TARGETS)

fuzz_certs: fuzz_certs.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)
