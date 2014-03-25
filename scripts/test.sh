#!/bin/sh
# Build script for Travis CI

if test -z $TRAVIS_BUILD_DIR; then
	TRAVIS_BUILD_DIR=$PWD
fi

cd $TRAVIS_BUILD_DIR

TARGET=check

DEPS="libgmp-dev"

case "$TEST" in
default)
	# should be the default, but lets make sure
	CONFIG="--with-printf-hooks=glibc"
	;;
openssl)
	CONFIG="--disable-defaults --enable-tools --enable-openssl"
	DEPS="libssl-dev"
	;;
gcrypt)
	CONFIG="--disable-defaults --enable-tools --enable-gcrypt --enable-pkcs1"
	DEPS="libgcrypt11-dev"
	;;
printf-builtin)
	CONFIG="--with-printf-hooks=builtin"
	;;
all)
	CONFIG="--enable-all --disable-android-dns --disable-android-log
			--disable-dumm --disable-kernel-pfroute --disable-keychain
			--disable-lock-profiler --disable-maemo --disable-padlock
			--disable-osx-attr --disable-tkm --disable-uci"
	if test "$LEAK_DETECTIVE" = "yes"; then
		# libgcrypt can't be deinitialized
		CONFIG="$CONFIG --disable-gcrypt"
		# libunwind causes threads to be cleaned up after LD is disabled
		CONFIG="$CONFIG --disable-unwind-backtraces"
	fi
	# not enabled on the build server
	CONFIG="$CONFIG --disable-af-alg"
	# TODO: enable? perhaps via coveralls.io (cpp-coveralls)?
	CONFIG="$CONFIG --disable-coverage"
	DEPS="$DEPS libcurl4-gnutls-dev libsoup2.4-dev libunbound-dev libldns-dev
		  libmysqlclient-dev libsqlite3-dev clearsilver-dev libfcgi-dev
		  libnm-glib-dev libnm-glib-vpn-dev libpcsclite-dev libpam0g-dev
		  binutils-dev libunwind7-dev"
	;;
dist)
	TARGET=distcheck
	;;
*)
	echo "$0: unknown test $TEST" >&2
	exit 1
	;;
esac

if test "$1" = "deps"; then
	sudo apt-get install -qq $DEPS
	exit $?
fi

CONFIG="$CONFIG
	--enable-silent-rules
	--enable-test-vectors
	--enable-monolithic=${MONOLITHIC-no}
	--enable-leak-detective=${LEAK_DETECTIVE-no}"

echo "$ ./configure $CONFIG && make $TARGET"
./configure $CONFIG && make -j4 $TARGET
