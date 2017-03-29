AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-DPLUGINDIR=\""$(abs_top_builddir)/src/libstrongswan/plugins\"" \
	-DPLUGINS="\"${fuzz_plugins}\""

noinst_PROGRAMS = fuzz_certs

fuzz_certs_SOURCES = fuzz_certs.c

fuzz_certs_LDFLAGS = ${libfuzzer} -lstdc++

fuzz_certs_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
