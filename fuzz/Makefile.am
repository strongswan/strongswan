AM_CPPFLAGS = @CPPFLAGS@ \
	@FUZZING_CFLAGS@ \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libimcv \
	-I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libtpmtss \
	-I$(top_srcdir)/src/libtnccs \
	-I$(top_srcdir)/src/libtnccs/plugins/tnccs_20 \
	-I$(top_srcdir)/src/libradius

fuzz_cppflags_def = ${AM_CPPFLAGS} \
	-DPLUGINS="\"${fd_plugins}\""

fuzz_cppflags_cus = ${AM_CPPFLAGS} \
	-DPLUGINS="\"${fc_plugins}\""

fuzz_ldflags = ${libfuzzer} \
	$(top_builddir)/src/libstrongswan/.libs/libstrongswan.a \
	@FUZZING_LDFLAGS@

if USE_OPENSSL
fuzz_ldflags += -Wl,-Bstatic -lcrypto -Wl,-Bdynamic
endif

if USE_GMP
fuzz_ldflags += -Wl,-Bstatic -lgmp -Wl,-Bdynamic
endif

pa_tnc_ldflags = \
	$(top_builddir)/src/libimcv/.libs/libimcv.a \
	$(top_builddir)/src/libtncif/.libs/libtncif.a \
	$(top_builddir)/src/libtpmtss/.libs/libtpmtss.a \
	$(fuzz_ldflags)

pb_tnc_ldflags = \
	$(top_builddir)/src/libtnccs/.libs/libtnccs.a \
	$(top_builddir)/src/libtncif/.libs/libtncif.a \
	$(fuzz_ldflags)

charon_ldflags = \
	$(top_builddir)/src/libcharon/.libs/libcharon.a \
	$(top_builddir)/src/libradius/.libs/libradius.a \
	$(fuzz_ldflags)

# fuzzers that use crypto plugins in a significant way
fuzzers_with_plugins = \
	fuzz_certs fuzz_crls fuzz_ocsp_req fuzz_ocsp_rsp

fuzzers_with_def = $(fuzzers_with_plugins:%=%_def)
fuzzers_with_cus = $(fuzzers_with_plugins:%=%_cus)

fuzzers_no_plugins = \
	fuzz_ids fuzz_ike fuzz_pa_tnc fuzz_pb_tnc fuzz_vici

ALL_FUZZERS=$(fuzzers_with_def) $(fuzzers_with_cus) $(fuzzers_no_plugins)

all-local: $(ALL_FUZZERS)

CLEANFILES=$(ALL_FUZZERS)

fuzz_certs_def: fuzz_certs.c ${libfuzzer}
	$(CC) $(fuzz_cppflags_def) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_certs_cus: fuzz_certs.c ${libfuzzer}
	$(CC) $(fuzz_cppflags_cus) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_crls_def: fuzz_crls.c ${libfuzzer}
	$(CC) $(fuzz_cppflags_def) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_crls_cus: fuzz_crls.c ${libfuzzer}
	$(CC) $(fuzz_cppflags_cus) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_ocsp_req_def: fuzz_ocsp_req.c ${libfuzzer}
	$(CC) $(fuzz_cppflags_def) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_ocsp_req_cus: fuzz_ocsp_req.c ${libfuzzer}
	$(CC) $(fuzz_cppflags_cus) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_ocsp_rsp_def: fuzz_ocsp_rsp.c ${libfuzzer}
	$(CC) $(fuzz_cppflags_def) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_ocsp_rsp_cus: fuzz_ocsp_rsp.c ${libfuzzer}
	$(CC) $(fuzz_cppflags_cus) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_pa_tnc: fuzz_pa_tnc.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(pa_tnc_ldflags)

fuzz_pb_tnc: fuzz_pb_tnc.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(pb_tnc_ldflags)

fuzz_ids: fuzz_ids.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_ike: fuzz_ike.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(charon_ldflags)

fuzz_vici: fuzz_vici.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(charon_ldflags)

noinst_LIBRARIES = libFuzzerLocal.a
libFuzzerLocal_a_SOURCES = libFuzzerLocal.c
libFuzzerLocal_a_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

check: all
	$(TESTS_ENVIRONMENT) \
	for f in $(ALL_FUZZERS); do \
		corpus=$${f#fuzz_}; \
		corpus=$${corpus%_def}; \
		corpus=$${corpus%_cus}; \
		initial=$(FUZZING_CORPORA)/$${corpus}; \
		crashes=$${initial}-crash; \
		test ! -d $${initial} || ./$$f $${initial}/* || exit 1; \
		test ! -d $${crashes} || ./$$f $${crashes}/* || exit 1; \
	done
