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

$LIBTOOLIZE --force &&
aclocal &&
autoheader &&
automake -a &&
autoconf

