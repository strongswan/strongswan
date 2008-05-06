
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libcharon-med-db.la
libcharon_med_db_la_SOURCES = med_db_plugin.h med_db_plugin.c \
			      med_db_creds.h med_db_creds.c \
			      med_db_config.h med_db_config.c \
			      med_db_pubkey.h med_db_pubkey.c
libcharon_med_db_la_LDFLAGS = -module

