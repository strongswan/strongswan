#!/bin/sh
# Build script for Travis CI

if test -z $TRAVIS_BUILD_DIR; then
	TRAVIS_BUILD_DIR=$PWD
fi

cd $TRAVIS_BUILD_DIR

TARGET=check

case "$TEST" in
default)
	;;
openssl)
	CONFIG="--disable-defaults --enable-tools --enable-openssl"
	;;
gcrypt)
	CONFIG="--disable-defaults --enable-tools --enable-gcrypt --enable-pkcs1"
	;;
all)
	CONFIG="--enable-all --disable-android-dns --disable-android-log
			--disable-dumm --disable-kernel-pfroute --disable-keychain
			--disable-lock-profiler --disable-maemo --disable-padlock
			--disable-osx-attr --disable-tkm --disable-uci"
	# not enabled on the build server
	CONFIG="$CONFIG --disable-af-alg"
	# TODO: add tests for different printf implementations?
	CONFIG="$CONFIG --disable-vstr"
	# TODO: enable? perhaps via coveralls.io (cpp-coveralls)?
	CONFIG="$CONFIG --disable-coverage"
	;;
dist)
	TARGET=distcheck
	;;
*)
	echo "$0: unknown test $TEST" >&2
	exit 1
	;;
esac

CONFIG="$CONFIG
	--enable-silent-rules
	--enable-test-vectors
	--enable-monolithic=${MONOLITHIC-no}
	--enable-leak-detective=${LEAK_DETECTIVE-no}"

echo "$ ./configure $CONFIG && make $TARGET"
./configure $CONFIG && make $TARGET
