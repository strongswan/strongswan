#!/bin/sh
# Build script for Travis CI

if test -z $TRAVIS_BUILD_DIR; then
	TRAVIS_BUILD_DIR=$PWD
fi

cd $TRAVIS_BUILD_DIR

TARGET=check

DEPS="libgmp-dev"

CFLAGS="-g -O2 -Wall -Wno-format -Wno-format-security -Wno-pointer-sign -Werror"

case "$TEST" in
default)
	# should be the default, but lets make sure
	CONFIG="--with-printf-hooks=glibc"
	;;
openssl)
	CONFIG="--disable-defaults --enable-pki --enable-openssl"
	DEPS="libssl-dev"
	;;
gcrypt)
	CONFIG="--disable-defaults --enable-pki --enable-gcrypt --enable-pkcs1"
	DEPS="libgcrypt11-dev"
	;;
printf-builtin)
	CONFIG="--with-printf-hooks=builtin"
	;;
all)
	CONFIG="--enable-all --disable-android-dns --disable-android-log
			--disable-dumm --disable-kernel-pfroute --disable-keychain
			--disable-lock-profiler --disable-maemo --disable-padlock
			--disable-osx-attr --disable-tkm --disable-uci --disable-aikgen
			--disable-systemd
			--disable-svc --disable-dbghelp-backtraces --disable-socket-win
			--disable-kernel-wfp --disable-kernel-iph --disable-winhttp"
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
		  binutils-dev libunwind7-dev libjson0-dev"
	;;
win*)
	CONFIG="--disable-defaults --enable-svc --enable-ikev2
			--enable-ikev1 --enable-static --enable-test-vectors --enable-nonce
			--enable-constraints --enable-revocation --enable-pem --enable-pkcs1
			--enable-pkcs8 --enable-x509 --enable-pubkey --enable-acert
			--enable-eap-tnc --enable-eap-ttls --enable-eap-identity
			--enable-tnccs-20 --enable-imc-attestation --enable-imv-attestation
			--enable-imc-os --enable-imv-os --enable-tnc-imv --enable-tnc-imc
			--enable-pki --enable-swanctl --enable-socket-win"
	# no make check for Windows binaries
	TARGET=
	CFLAGS="$CFLAGS -mno-ms-bitfields"
	DEPS="gcc-mingw-w64-base mingw-w64-dev"
	case "$TEST" in
	win64)
		CONFIG="--host=x86_64-w64-mingw32 $CONFIG"
		DEPS="gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 $DEPS"
		CC="x86_64-w64-mingw32-gcc"
		;;
	win32)
		CONFIG="--host=i686-w64-mingw32 $CONFIG"
		DEPS="gcc-mingw-w64-i686 binutils-mingw-w64-i686 $DEPS"
		CC="i686-w64-mingw32-gcc"
		;;
	esac
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

echo "$ CC="$CC" CFLAGS="$CFLAGS" ./configure $CONFIG && make $TARGET"
CC="$CC" CFLAGS="$CFLAGS" ./configure $CONFIG && make -j4 $TARGET
