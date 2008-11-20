
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon ${nm_CFLAGS}

AM_CFLAGS = -rdynamic

plugin_LTLIBRARIES = libstrongswan-nm.la
libstrongswan_nm_la_SOURCES = \
  nm_plugin.h nm_plugin.c nm_service.h nm_service.c nm_creds.h nm_creds.c
libstrongswan_nm_la_LDFLAGS = -module
libstrongswan_nm_la_LIBADD = ${nm_LIBS}


# build gnome/configure and friends for distribution

EXTRA_DIST = gnome/configure gnome/po/LINGUAS gnome/po/POTFILES.in gnome/po/Makefile.in.in \
	gnome/ltmain.sh gnome/config.h.in gnome/depcomp gnome/Makefile.in \
	gnome/compile gnome/intltool-merge.in gnome/configure.in gnome/install-sh \
	gnome/aclocal.m4 gnome/Makefile.am gnome/autogen.sh \
	gnome/properties/Makefile.in gnome/properties/nm-strongswan-dialog.glade \
	gnome/properties/Makefile.am gnome/properties/nm-strongswan.c \
	gnome/properties/nm-strongswan.h gnome/intltool-update.in gnome/config.guess \
	gnome/nm-strongswan-service.name.in gnome/nm-strongswan-service.conf \
	gnome/mkinstalldirs gnome/auth-dialog/Makefile.in \
	gnome/auth-dialog/Makefile.am gnome/auth-dialog/main.c gnome/intltool-extract.in \
	gnome/config.sub gnome/missing

gnome/configure :	gnome/configure.in
					(cd `dirname $<` && ./autogen.sh)
