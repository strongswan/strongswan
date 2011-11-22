
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif

ipseclib_LTLIBRARIES = libtnccs.la

libtnccs_la_LIBADD = $(top_builddir)/src/libtncif/libtncif.la

libtnccs_la_SOURCES = \
tnc/tnc.h tnc/tnc.c \
tnc/imc/imc.h tnc/imc/imc_manager.h \
tnc/imv/imv.h tnc/imv/imv_manager.h \
tnc/imv/imv_recommendations.h tnc/imv/imv_recommendations.c \
tnc/tnccs/tnccs.h tnc/tnccs/tnccs.c \
tnc/tnccs/tnccs_manager.h tnc/tnccs/tnccs_manager.c

EXTRA_DIST = Android.mk
