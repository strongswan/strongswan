#!/bin/sh

LIBTOOLIZE=`which glibtoolize 2>/dev/null`
case "$LIBTOOLIZE" in
	/* )	;;
	*  )	LIBTOOLIZE=`which libtoolize 2>/dev/null`
		case "$LIBTOOLIZE" in
			/* )	;;
			*  )	LIBTOOLIZE=libtoolize
				;;
		esac
		;;
esac

autoheader &&
$LIBTOOLIZE --force &&
aclocal &&
automake -a &&
autoconf

