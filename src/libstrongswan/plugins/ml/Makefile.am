AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-ml.la
else
plugin_LTLIBRARIES = libstrongswan-ml.la
endif

libstrongswan_ml_la_SOURCES = \
	ml_bitpacker.c ml_bitpacker.h \
	ml_kem.c ml_kem.h \
	ml_dsa_public_key.c ml_dsa_public_key.h \
	ml_dsa_private_key.c ml_dsa_private_key.h \
	ml_kem_params.c ml_kem_params.h \
	ml_dsa_params.c ml_dsa_params.h \
	ml_plugin.h ml_plugin.c \
	ml_poly.c ml_poly.h \
	ml_dsa_poly.c ml_dsa_poly.h \
	ml_utils.c ml_utils.h

libstrongswan_ml_la_LDFLAGS = -module -avoid-version
