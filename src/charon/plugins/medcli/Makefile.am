
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-medcli.la
libstrongswan_medcli_la_SOURCES = medcli_plugin.h medcli_plugin.c \
			      medcli_creds.h medcli_creds.c \
			      medcli_config.h medcli_config.c \
			      medcli_listener.h medcli_listener.c
libstrongswan_medcli_la_LDFLAGS = -module -avoid-version

