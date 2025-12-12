AC_PREREQ([2.69])

AC_INIT([NetworkManager-strongswan],[1.6.4],[info@strongswan.org],[NetworkManager-strongswan])
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
LT_INIT([disable-static])
PKG_PROG_PKG_CONFIG
AC_PATH_PROG(GLIB_COMPILE_RESOURCES, glib-compile-resources)

dnl
dnl Required headers
dnl
AC_CHECK_HEADERS(fcntl.h paths.h sys/ioctl.h sys/time.h syslog.h unistd.h)

dnl
dnl Checks for typedefs, structures, and compiler characteristics.
dnl
AC_TYPE_MODE_T
AC_TYPE_PID_T

dnl
dnl Checks for library functions.
dnl
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_CHECK_FUNCS(select socket uname)

LIBS=""
AC_SEARCH_LIBS([dlopen], [dl dld], [DL_LIBS=$LIBS])
AC_SUBST([DL_LIBS])

AM_GNU_GETTEXT_VERSION([0.19])
AM_GNU_GETTEXT([external])

GETTEXT_PACKAGE=NetworkManager-strongswan
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE", [Gettext package])

PKG_CHECK_MODULES(GTK, gtk+-3.0 >= 3.0)
PKG_CHECK_MODULES(LIBSECRET, libsecret-1)

AC_ARG_WITH(
	[charon],
	AS_HELP_STRING([--with-charon=file],[path to the strongSwan charon NetworkManager backend]),
	[AC_SUBST(charon, "$withval")],
	[AC_SUBST(charon, "${libexecdir}/ipsec/charon-nm")]
)
AC_ARG_WITH(
	[nm-libexecdir],
	AS_HELP_STRING([--nm-libexecdir=path],[use custom path where the auth dialog is installed]),
	[nm_libexecdir="$withval"], []
)
AC_ARG_WITH(
	[nm-plugindir],
	AS_HELP_STRING([--nm-plugindir=path],[use custom path where the NM plugin is installed]),
	[nm_plugindir="$withval"], []
)
AC_ARG_ENABLE(
	[nm-absolute-paths],
	AS_HELP_STRING([--enable-nm-absolute-paths],[use absolute paths for NM plugins in the .name file])
)
AC_ARG_WITH(
	[gtk4],
	AS_HELP_STRING([--with-gtk4], [build NetworkManager-strongswan with libnma-gtk4 support]),
	[], [with_gtk4=no]
)

AM_CONDITIONAL(WITH_GTK4, test "$with_gtk4" != no)

PKG_CHECK_MODULES(LIBNM, libnm >= 1.1.0)
PKG_CHECK_MODULES(LIBNMA, libnma >= 1.1.0)

if test x"$with_gtk4" != xno; then
	PKG_CHECK_MODULES(GTK4, gtk4 >= 4.0)
	PKG_CHECK_MODULES(LIBNMA_GTK4, libnma-gtk4 >= 1.8.33)
fi

if test -z "$nm_libexecdir"; then
	nm_libexecdir=$($PKG_CONFIG --variable=exec_prefix libnm)/lib/NetworkManager
fi
if test -z "$nm_plugindir"; then
	nm_plugindir=$($PKG_CONFIG --variable=libdir libnm)/NetworkManager
fi

AC_SUBST(nm_libexecdir)
AC_SUBST(nm_plugindir)
test x"$enable_nm_absolute_paths" = x"yes" && nm_plugindir_abs="$(nm_plugindir)/"
AC_SUBST(nm_plugindir_abs)

nmvpnservicedir=$($PKG_CONFIG --variable=vpnservicedir libnm)
AC_SUBST(nmvpnservicedir)

NM_COMPILER_WARNINGS

AC_CONFIG_FILES([
Makefile
properties/Makefile
auth-dialog/Makefile
po/Makefile.in
])
AC_OUTPUT
