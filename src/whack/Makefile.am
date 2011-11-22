ipsec_PROGRAMS = whack

whack_SOURCES = \
whack.c whack.h

INCLUDES = \
-I$(top_srcdir)/src/libstrongswan \
-I$(top_srcdir)/src/libfreeswan \
-I$(top_srcdir)/src/libhydra \
-I$(top_srcdir)/src/pluto

whack_LDADD = \
$(top_builddir)/src/libstrongswan/libstrongswan.la \
$(top_builddir)/src/libfreeswan/libfreeswan.a

AM_CFLAGS = -DDEBUG -DIPSEC_PIDDIR=\"${piddir}\"

EXTRA_DIST = Android.mk
