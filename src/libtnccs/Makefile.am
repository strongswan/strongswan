
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libtncif

ipseclib_LTLIBRARIES = libtnccs.la

libtnccs_la_LIBADD = $(top_builddir)/src/libtncif/libtncif.la

libtnccs_la_SOURCES = \
	imc/imc.h imc/imc_manager.h \
	imv/imv.h imv/imv_manager.h \
	imv/imv_recommendations.h imv/imv_recommendations.c 

