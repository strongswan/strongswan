
INCLUDES = -I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = -rdynamic

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-agent.la
else
plugin_LTLIBRARIES = libstrongswan-agent.la
libstrongswan_agent_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la
endif

libstrongswan_agent_la_SOURCES = \
	agent_plugin.h agent_plugin.c \
	agent_private_key.c agent_private_key.h

libstrongswan_agent_la_LDFLAGS = -module -avoid-version
