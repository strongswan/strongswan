AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-auth-els.la
else
plugin_LTLIBRARIES = libstrongswan-auth-els.la
endif

libstrongswan_auth_els_la_SOURCES = \
	auth_els_configs.h auth_els_configs.c \
	auth_els_kernel_fc_sp.h auth_els_kernel_fc_sp.c \
	auth_els_ike.h auth_els_ike.c \
	auth_els_socket.h auth_els_socket.c \
	auth_els_plugin.h auth_els_plugin.c \
	auth_els_utils.h

libstrongswan_auth_els_la_LDFLAGS = -module -avoid-version


