
# ARG_ENABL_SET(option, help)
# ---------------------------
# Create a --enable-$1 option with helptext, set a variable $1 to true/false
AC_DEFUN([ARG_ENABL_SET],
	[AC_ARG_ENABLE(
		[$1],
		AS_HELP_STRING([--enable-$1], [$2]),
		[if test x$enableval = xyes; then
			patsubst([$1], [-], [_])=true
		 else
			patsubst([$1], [-], [_])=false
		fi],
		patsubst([$1], [-], [_])=false
	)]
)

# ARG_DISBL_SET(option, help)
# ---------------------------
# Create a --disable-$1 option with helptext, set a variable $1 to true/false
AC_DEFUN([ARG_DISBL_SET],
	[AC_ARG_ENABLE(
		[$1],
		AS_HELP_STRING([--disable-$1], [$2]),
		[if test x$enableval = xyes; then
			patsubst([$1], [-], [_])=true
		 else
			patsubst([$1], [-], [_])=false
		fi],
		patsubst([$1], [-], [_])=true
	)]
)
