
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon -I$(top_srcdir)/src/libtncif

AM_CFLAGS = -DUSE_TNC -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-tnc-imc.la
else
plugin_LTLIBRARIES = libstrongswan-tnc-imc.la
endif

libstrongswan_tnc_imc_la_SOURCES = \
	tnc_imc_plugin.h tnc_imc_plugin.c tnc_imc.h tnc_imc.c \
	tnc_imc_manager.h tnc_imc_manager.c tnc_imc_bind_function.c

libstrongswan_tnc_imc_la_LDFLAGS = -module -avoid-version

