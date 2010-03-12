ipsec_PROGRAMS = charon

charon_SOURCES = \
charon.c

INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libcharon
AM_CFLAGS = \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DIPSEC_PIDDIR=\"${piddir}\"
charon_LDADD = $(top_builddir)/src/libcharon/libcharon.la -lm $(PTHREAD) $(DLLIB)

#EXTRA_DIST = Android.mk

