AC_PREREQ(2.52)

AC_INIT(NetworkManager-strongswan, 1.3.2, martin@strongswan.org, NetworkManager-strongswan)
AM_INIT_AUTOMAKE([subdir-objects])
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

dnl
dnl Require programs
dnl
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LIBTOOL

dnl
dnl Required headers
dnl
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h paths.h sys/ioctl.h sys/time.h syslog.h unistd.h)

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_HEADER_TIME

dnl
dnl Checks for library functions.
dnl
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(select socket uname)

GETTEXT_PACKAGE=NetworkManager-strongswan
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

IT_PROG_INTLTOOL([0.35])
AM_GLIB_GNU_GETTEXT

PKG_CHECK_MODULES(GTK, gtk+-2.0 >= 2.6)
PKG_CHECK_MODULES(LIBGNOMEUI, libgnomeui-2.0)
PKG_CHECK_MODULES(LIBSECRET, libsecret-1)

PKG_CHECK_MODULES(LIBNM_GLIB, NetworkManager >= 1.1.0 libnm-util libnm-glib libnm-glib-vpn)

PKG_CHECK_MODULES(LIBNM, libnm >= 1.1.0)
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MIN_REQUIRED=NM_VERSION_1_2"
LIBNM_CFLAGS="$LIBNM_CFLAGS -DNM_VERSION_MAX_ALLOWED=NM_VERSION_1_2"

NM_COMPILER_WARNINGS

AC_CONFIG_FILES([
Makefile
properties/Makefile
auth-dialog/Makefile
po/Makefile.in
])
AC_OUTPUT
