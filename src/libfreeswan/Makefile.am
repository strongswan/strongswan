noinst_LIBRARIES = libfreeswan.a
libfreeswan_a_SOURCES = \
addrtoa.c addrtot.c addrtypeof.c anyaddr.c atoaddr.c atoasr.c \
atosubnet.c atoul.c copyright.c datatot.c freeswan.h \
goodmask.c initaddr.c initsaid.c initsubnet.c internal.h ipsec_param.h \
pfkey_v2_build.c pfkey_v2_debug.c \
pfkey_v2_ext_bits.c pfkey_v2_parse.c portof.c rangetoa.c \
pfkey.h pfkeyv2.h rangetosubnet.c sameaddr.c \
satot.c subnetof.c subnettoa.c subnettot.c \
subnettypeof.c ttoaddr.c ttodata.c ttoprotoport.c ttosa.c ttosubnet.c ttoul.c \
ultoa.c ultot.c

INCLUDES = \
-I$(top_srcdir)/src/libstrongswan \
-I$(top_srcdir)/src/libhydra \
-I$(top_srcdir)/src/pluto

dist_man3_MANS = anyaddr.3 atoaddr.3 atoasr.3 atoul.3 goodmask.3 initaddr.3 initsubnet.3 \
                 portof.3 rangetosubnet.3 sameaddr.3 subnetof.3 \
                 ttoaddr.3 ttodata.3 ttosa.3 ttoul.3

EXTRA_DIST = Android.mk
