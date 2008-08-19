noinst_PROGRAMS = fips_signer
fips_signer_SOURCES = fips_signer.c
fips_signer_LDADD = ../libstrongswan.la

BUILT_SOURCES = fips_signature.h
CLEANFILES = fips_signature.h fips_signer
INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = -DSTRONGSWAN_CONF=\"${strongswan_conf}\" \
            -DPLUGINDIR=\"${top_srcdir}/src/libstrongswan/plugins\"
if USE_SHA1
  AM_CFLAGS += -DUSE_SHA1
endif

if USE_OPENSSL
  AM_CFLAGS += -DUSE_OPENSSL
endif

fips_signature.h : fips_signer
		   ./fips_signer
