AC_INIT(strongswan-applet, 1.0.1)
AM_INIT_AUTOMAKE

# Programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Headers
AC_HEADER_STDC

# Library dependencies
PKG_CHECK_MODULES(HILDON, hildon-1 hildon-fm-2 hildon-control-panel libhildondesktop-1)
AC_SUBST(HILDON_CFLAGS)
AC_SUBST(HILDON_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-glib-1 >= 0.60)
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(OSSO, osso-af-settings >= 0.8.5 libosso >= 0.9.17 gnome-vfs-2.0 >= 2.8.4.11 gnome-vfs-module-2.0 >= 2.8.4.11)
AC_SUBST(OSSO_CFLAGS)
AC_SUBST(OSSO_LIBS)

# Application icon install directories
icon_18x18dir=$datadir/icons/hicolor/18x18/hildon
icon_24x24dir=$datadir/icons/hicolor/24x24/hildon
icon_32x32dir=$datadir/icons/hicolor/32x32/hildon
icon_48x48dir=$datadir/icons/hicolor/48x48/hildon
icon_scalabledir=$datadir/icons/hicolor/scalable/hildon

# Hildon control panel plugin install directories
pluginlibdir=`$PKG_CONFIG hildon-control-panel --variable=pluginlibdir`
plugindesktopentrydir=`$PKG_CONFIG hildon-control-panel --variable=plugindesktopentrydir`

# Hildon status widget install directories
statuslibdir=`$PKG_CONFIG libhildondesktop-1 --variable=hildondesktoplibdir`
statusdesktopentrydir=`$PKG_CONFIG libhildondesktop-1 --variable=hildonstatusmenudesktopentrydir`

AC_SUBST(icon_18x18dir)
AC_SUBST(icon_24x24dir)
AC_SUBST(icon_32x32dir)
AC_SUBST(icon_48x48dir)
AC_SUBST(icon_scalabledir)
AC_SUBST(pluginlibdir)
AC_SUBST(plugindesktopentrydir)
AC_SUBST(statuslibdir)
AC_SUBST(statusdesktopentrydir)

AC_OUTPUT(
	  Makefile \
	  src/Makefile \
	  data/Makefile
)
