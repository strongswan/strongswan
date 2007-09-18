ipsec_PROGRAMS = openac
openac_SOURCES = openac.c build.c build.h
dist_man_MANS = openac.8

INCLUDES = -I$(top_srcdir)/src/libstrongswan
AM_CFLAGS = -DIPSEC_CONFDIR=\"${confdir}\"
openac_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lgmp

