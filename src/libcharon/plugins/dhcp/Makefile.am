
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libcharon

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-dhcp.la
else
plugin_LTLIBRARIES = libstrongswan-dhcp.la
endif

libstrongswan_dhcp_la_SOURCES = dhcp_plugin.h dhcp_plugin.c

libstrongswan_dhcp_la_LDFLAGS = -module -avoid-version
