AM_CPPFLAGS = @CPPFLAGS@ \
	@FUZZING_CFLAGS@ \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libimcv \
	-I$(top_srcdir)/src/libtncif \
	-I$(top_srcdir)/src/libtpmtss \
	-I$(top_srcdir)/src/libtnccs \
	-I$(top_srcdir)/src/libtnccs/plugins/tnccs_20 \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS="\"${fuzz_plugins}\""

fuzz_ldflags = ${libfuzzer} \
	$(top_builddir)/src/libstrongswan/.libs/libstrongswan.a \
	-Wl,-Bstatic -lcrypto -Wl,-Bdynamic \
	@FUZZING_LDFLAGS@

pa_tnc_ldflags = \
	$(top_builddir)/src/libimcv/.libs/libimcv.a \
	$(top_builddir)/src/libtncif/.libs/libtncif.a \
	$(top_builddir)/src/libtpmtss/.libs/libtpmtss.a \
	$(fuzz_ldflags)

pb_tnc_ldflags = \
	$(top_builddir)/src/libtnccs/.libs/libtnccs.a \
	$(top_builddir)/src/libtncif/.libs/libtncif.a \
	$(fuzz_ldflags)

ike_ldflags = \
	$(top_builddir)/src/libcharon/.libs/libcharon.a \
	$(fuzz_ldflags)

FUZZ_TARGETS=fuzz_certs fuzz_crls fuzz_ocsp_req fuzz_ocsp_rsp \
	fuzz_ids fuzz_pa_tnc fuzz_pb_tnc fuzz_ike

all-local: $(FUZZ_TARGETS)

CLEANFILES=$(FUZZ_TARGETS)

fuzz_certs: fuzz_certs.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_crls: fuzz_crls.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_ocsp_req: fuzz_ocsp_req.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_ocsp_rsp: fuzz_ocsp_rsp.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_ids: fuzz_ids.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(fuzz_ldflags)

fuzz_pa_tnc: fuzz_pa_tnc.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(pa_tnc_ldflags)

fuzz_pb_tnc: fuzz_pb_tnc.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(pb_tnc_ldflags)

fuzz_ike: fuzz_ike.c ${libfuzzer}
	$(CC) $(AM_CPPFLAGS) $(CFLAGS) -o $@ $< $(ike_ldflags)

noinst_LIBRARIES = libFuzzerLocal.a
libFuzzerLocal_a_SOURCES = libFuzzerLocal.c
libFuzzerLocal_a_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la

check: all
	for f in $(FUZZ_TARGETS); do \
		corpus=$${f#fuzz_}; \
		initial=$(FUZZING_CORPORA)/$${corpus}; \
		crashes=$${initial}-crash; \
		test ! -d $${initial} || ./$$f $${initial}/* || exit 1; \
		test ! -d $${crashes} || ./$$f $${crashes}/* || exit 1; \
	done
