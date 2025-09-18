#!/bin/sh
# Build script for CI

build_botan()
{
	# same revision used in the build recipe of the testing environment
	BOTAN_REV=3.7.1
	BOTAN_DIR=$DEPS_BUILD_DIR/botan

	if test -d "$BOTAN_DIR"; then
		return
	fi

	echo "$ build_botan()"

	# if the leak detective is enabled we have to disable threading support
	# (used for std::async) as that causes invalid frees somehow, the
	# locking allocator causes a static leak via the first function that
	# references it (e.g. crypter or hasher), so we disable that too
	if test "$LEAK_DETECTIVE" = "yes"; then
		BOTAN_CONFIG="--without-os-features=threads
					  --disable-modules=locking_allocator"
	fi
	# disable some larger modules we don't need for the tests and deprecated
	# ones, except for MD5, which we need for TLS 1.0/1.1
	BOTAN_CONFIG="$BOTAN_CONFIG --disable-modules=pkcs11,tls,x509,xmss
				  --disable-deprecated-features --enable-modules=md5
				  --prefix=$DEPS_PREFIX"

	git clone https://github.com/randombit/botan.git $BOTAN_DIR &&
	cd $BOTAN_DIR &&
	git checkout -qf $BOTAN_REV &&
	./configure.py --amalgamation $BOTAN_CONFIG &&
	make -j$(nproc) libs >/dev/null &&
	sudo make install >/dev/null &&
	sudo ldconfig || exit $?
	cd -
}

build_wolfssl()
{
	WOLFSSL_REV=v5.8.2-stable
	WOLFSSL_DIR=$DEPS_BUILD_DIR/wolfssl

	if test -d "$WOLFSSL_DIR"; then
		return
	fi

	echo "$ build_wolfssl()"

	WOLFSSL_CFLAGS="-DWOLFSSL_PUBLIC_MP -DWOLFSSL_DES_ECB -DHAVE_AES_ECB \
					-DHAVE_ECC_BRAINPOOL -DWOLFSSL_MIN_AUTH_TAG_SZ=8 \
					-DRSA_MIN_SIZE=1024"
	WOLFSSL_CONFIG="--prefix=$DEPS_PREFIX
					--disable-crypttests --disable-examples
					--enable-aesccm --enable-aesctr --enable-aescfb --enable-camellia
					--enable-curve25519 --enable-curve448 --enable-des3
					--enable-ecccustcurves --enable-ed25519 --enable-ed448
					--enable-keygen --enable-mlkem --with-max-rsa-bits=8192
					--enable-md4 --enable-rsapss --enable-sha3 --enable-shake256"

	git clone https://github.com/wolfSSL/wolfssl.git $WOLFSSL_DIR &&
	cd $WOLFSSL_DIR &&
	git checkout -qf $WOLFSSL_REV &&
	./autogen.sh &&
	./configure C_EXTRA_FLAGS="$WOLFSSL_CFLAGS" $WOLFSSL_CONFIG &&
	make -j$(nproc) >/dev/null &&
	sudo make install >/dev/null &&
	sudo ldconfig || exit $?
	cd -
}

build_tss2()
{
	TSS2_REV=3.2.3
	TSS2_PKG=tpm2-tss-$TSS2_REV
	TSS2_DIR=$DEPS_BUILD_DIR/$TSS2_PKG
	TSS2_SRC=https://github.com/tpm2-software/tpm2-tss/releases/download/$TSS2_REV/$TSS2_PKG.tar.gz

	if test -d "$TSS2_DIR"; then
		return
	fi

	echo "$ build_tss2()"

	curl -L $TSS2_SRC | tar xz -C $DEPS_BUILD_DIR &&
	cd $TSS2_DIR &&
	./configure --prefix=$DEPS_PREFIX --disable-doxygen-doc &&
	make -j$(nproc) >/dev/null &&
	sudo make install >/dev/null &&
	sudo ldconfig || exit $?
	cd -
}

build_openssl()
{
	SSL_REV=openssl-3.5.2
	SSL_DIR=$DEPS_BUILD_DIR/openssl
	SSL_INS=$DEPS_PREFIX/ssl
	SSL_OPT="-d shared no-dtls no-ssl3 no-zlib no-idea no-psk
			 no-tests enable-rfc3779 enable-ec_nistp_64_gcc_128"

	if test -d "$SSL_DIR"; then
		return
	fi

	if test "$LEAK_DETECTIVE" = "yes"; then
		# insist on compiling with gcc and debug information as symbols are
		# otherwise not found, but we can disable SRP (see below)
		SSL_OPT="$SSL_OPT no-srp CC=gcc -d"
	elif test "$CC" != "clang"; then
		# when using ASan with clang, llvm-symbolizer is used to resolve symbols
		# and this tool links libcurl, which in turn requires SRP, so we can
		# only disable it when not building with clang
		SSL_OPT="$SSL_OPT no-srp"
	fi

	echo "$ build_openssl()"

	git clone https://github.com/openssl/openssl.git --depth 1 -b $SSL_REV $SSL_DIR || exit $?

	if [ "$TEST" = "android" ]; then
		OPENSSL_SRC=${SSL_DIR} \
		NO_DOCKER=1 src/frontends/android/openssl/build.sh || exit $?
	else
		cd $SSL_DIR &&
		./config --prefix=$SSL_INS --openssldir=$SSL_INS --libdir=lib $SSL_OPT &&
		make -j$(nproc) >/dev/null &&
		sudo make install_sw >/dev/null &&
		sudo ldconfig || exit $?
		cd -
	fi
}

build_awslc()
{
	LC_REV=1.61.1
	LC_PKG=aws-lc-$LC_REV
	LC_DIR=$DEPS_BUILD_DIR/$LC_PKG
	LC_SRC=https://github.com/aws/aws-lc/archive/refs/tags/v${LC_REV}.tar.gz
	LC_BUILD=$LC_DIR/build
	LC_INS=$DEPS_PREFIX/ssl

	mkdir -p $LC_BUILD

	echo "$ build_awslc()"

	curl -L $LC_SRC | tar xz -C $DEPS_BUILD_DIR || exit $?

	cd $LC_BUILD &&
	cmake -GNinja -DCMAKE_INSTALL_PREFIX=$LC_INS .. &&
	ninja &&
	sudo ninja install || exit $?
	cd -
}

use_custom_openssl()
{
	CFLAGS="$CFLAGS -I$DEPS_PREFIX/ssl/include"
	export LDFLAGS="$LDFLAGS -L$DEPS_PREFIX/ssl/lib"
	export LD_LIBRARY_PATH="$DEPS_PREFIX/ssl/lib:$LD_LIBRARY_PATH"
	if test "$1" = "build-deps"; then
		case "$TEST" in
			openssl-awslc)
				build_awslc
				;;
			*)
				build_openssl
				;;
		esac
	fi
}

system_uses_openssl3()
{
	pkg-config --atleast-version=3.0.0 libcrypto
	return $?
}

prepare_system_openssl()
{
	# On systems that ship OpenSSL 3 (e.g. Ubuntu 22.04+), we require debug
	# symbols to whitelist leaks
	if test "$1" = "deps"; then
		echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted
			deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted
			deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted" | \
			sudo tee -a /etc/apt/sources.list.d/ddebs.list
		sudo apt-get install -qq ubuntu-dbgsym-keyring
		if [ "$ID" = "ubuntu" -a "$VERSION_ID" = "24.04" ]; then
			DEPS="$DEPS libssl3t64-dbgsym"
		else
			DEPS="$DEPS libssl3-dbgsym"
		fi
	fi
	if test "$LEAK_DETECTIVE" = "yes"; then
		# make sure we can properly whitelist functions with leak detective
		DEPS="$DEPS binutils-dev"
		CONFIG="$CONFIG --enable-bfd-backtraces"
	elif [ "$ID" = "ubuntu" -a "$VERSION_ID" != "24.04" ]; then
		# with ASan we have to use the (extremely) slow stack unwind as the
		# shipped version of the library is built with -fomit-frame-pointer
		export ASAN_OPTIONS=fast_unwind_on_malloc=0
	fi
}

: ${SRC_DIR=$PWD}
: ${BUILD_DIR=$PWD}
: ${DEPS_BUILD_DIR=$BUILD_DIR/..}
: ${DEPS_PREFIX=/usr/local}

if [ -e /etc/os-release ]; then
	. /etc/os-release
elif [ -e /usr/lib/os-release ]; then
	. /usr/lib/os-release
fi

TARGET=check

DEPS="libgmp-dev"

CFLAGS="-g -O2"

case "$TEST" in
default)
	# should be the default, but lets make sure
	CONFIG="--with-printf-hooks=glibc"
	if system_uses_openssl3; then
		prepare_system_openssl $1
	fi
	;;
openssl*)
	CONFIG="--disable-defaults --enable-pki --enable-openssl --enable-pem --enable-drbg"
	export TESTS_PLUGINS="test-vectors openssl! pem drbg"
	DEPS="libssl-dev"
	if test "$TEST" = "openssl-3"; then
		DEPS=""
		use_custom_openssl $1
	elif test "$TEST" = "openssl-awslc"; then
		DEPS="cmake ninja-build golang"
		use_custom_openssl $1
	elif system_uses_openssl3; then
		prepare_system_openssl $1
	else
		# the kdf plugin is necessary to build against older OpenSSL versions
		TESTS_PLUGINS="$TESTS_PLUGINS kdf"
	fi
	;;
gcrypt)
	CONFIG="--disable-defaults --enable-pki --enable-gcrypt --enable-random --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-gcm --enable-hmac --enable-kdf -enable-curve25519 --enable-x509 --enable-constraints"
	export TESTS_PLUGINS="test-vectors gcrypt! random pem pkcs1 pkcs8 gcm hmac kdf curve25519 x509 constraints"
	DEPS="libgcrypt20-dev"
	;;
botan)
	CONFIG="--disable-defaults --enable-pki --enable-botan --enable-pem --enable-hmac --enable-x509 --enable-constraints --enable-drbg"
	export TESTS_PLUGINS="test-vectors botan! pem hmac x509 constraints drbg"
	DEPS=""
	if test "$1" = "build-deps"; then
		build_botan
	fi
	;;
wolfssl)
	CONFIG="--disable-defaults --enable-pki --enable-wolfssl --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-x509 --enable-constraints --enable-drbg"
	export TESTS_PLUGINS="test-vectors wolfssl! pem pkcs1 pkcs8 x509 constraints drbg"
	# build with custom options to enable all the features the plugin supports
	DEPS=""
	if test "$1" = "build-deps"; then
		build_wolfssl
	fi
	;;
printf-builtin)
	CONFIG="--with-printf-hooks=builtin"
	if system_uses_openssl3; then
		prepare_system_openssl $1
	fi
	;;
all|alpine|codeql|coverage|sonarcloud|no-dbg|no-testable-ke)
	if [ "$TEST" = "codeql" ]; then
		# don't run tests, only analyze built code
		TARGET=
	fi
	if [ "$TEST" = "no-dbg" ]; then
		CFLAGS="$CFLAGS -DDEBUG_LEVEL=-1"
	fi
	CONFIG="--enable-all --disable-android-dns --disable-android-log
			--disable-kernel-pfroute --disable-keychain
			--disable-lock-profiler --disable-padlock --disable-fuzzing
			--disable-osx-attr --disable-tkm
			--disable-unwind-backtraces
			--disable-svc --disable-dbghelp-backtraces --disable-socket-win
			--disable-kernel-wfp --disable-kernel-iph --disable-winhttp"
	# not enabled on the build server
	CONFIG="$CONFIG --disable-af-alg"
	if test "$TEST" != "coverage"; then
		CONFIG="$CONFIG --disable-coverage"
	else
		DEPS="$DEPS lcov"
		TARGET="coverage"
	fi
	if [ "$TEST" = "no-testable-ke" ]; then
		CONFIG="$CONFIG --without-testable-ke"
	fi
	DEPS="$DEPS libcurl4-gnutls-dev libsoup-3.0-dev libunbound-dev libldns-dev
		  libmysqlclient-dev libsqlite3-dev clearsilver-dev libfcgi-dev
		  libldap2-dev libpcsclite-dev libpam0g-dev binutils-dev libnm-dev
		  libgcrypt20-dev libjson-c-dev libtspi-dev libsystemd-dev
		  libselinux1-dev libiptc-dev ruby-rubygems python3-build tox"
	if [ "$ID" = "ubuntu" -a "$VERSION_ID" = "22.04" -a "$1" = "build-deps" ]; then
		# python3-build is broken on 22.04 with venv (https://bugs.launchpad.net/ubuntu/+source/python-build/+bug/1992108)
		# while installing python3-virtualenv should help, it doesn't. as even
		# after uninstalling python3-venv, build prefers the latter
		sudo python3 -m pip install --upgrade build
	fi
	if [ "$TEST" = "alpine" ]; then
		# override the whole list for alpine
		DEPS="git gmp-dev openldap-dev curl-dev ldns-dev unbound-dev libsoup3-dev
			  libxml2-dev tpm2-tss-dev tpm2-tss-sys mariadb-dev wolfssl-dev
			  libgcrypt-dev botan3-dev pcsc-lite-dev networkmanager-dev
			  linux-pam-dev iptables-dev libselinux-dev binutils-dev libunwind-dev
			  ruby py3-setuptools py3-build py3-tox"
		# musl does not provide backtrace(), so use libunwind
		CONFIG="$CONFIG --enable-unwind-backtraces"
		# alpine doesn't have systemd
		CONFIG="$CONFIG --disable-systemd --disable-cert-enroll-timer"
		# no TrouSerS either
		CONFIG="$CONFIG --disable-tss-trousers --disable-aikgen"
		# and no Clearsilver
		CONFIG="$CONFIG --disable-fast --disable-manager --disable-medsrv"
	fi
	if test "$1" = "build-deps"; then
		build_botan
		build_wolfssl
		build_tss2
	fi
	use_custom_openssl $1
	;;
win*)
	CONFIG="--disable-defaults --enable-svc --enable-ikev2
			--enable-ikev1 --enable-static --enable-test-vectors --enable-nonce
			--enable-constraints --enable-revocation --enable-pem --enable-pkcs1
			--enable-pkcs8 --enable-x509 --enable-pubkey --enable-acert
			--enable-eap-tnc --enable-eap-ttls --enable-eap-identity
			--enable-eap-radius
			--enable-updown --enable-ext-auth --enable-libipsec --enable-pkcs11
			--enable-tnccs-20 --enable-imc-attestation --enable-imv-attestation
			--enable-imc-os --enable-imv-os --enable-tnc-imv --enable-tnc-imc
			--enable-pki --enable-swanctl --enable-socket-win
			--enable-kernel-iph --enable-kernel-wfp --enable-winhttp"
	# no make check for Windows binaries unless we run on a windows host
	if test "$APPVEYOR" != "True"; then
		TARGET=
	else
		CONFIG="$CONFIG --enable-openssl"
		CFLAGS="$CFLAGS -I$OPENSSL_DIR/include"
		LDFLAGS="-L$OPENSSL_DIR/lib"
		case "$IMG" in
		2015)
			# gcc/ld might be too old to find libeay32 via .lib instead of .dll
			LDFLAGS="-L$OPENSSL_DIR"
			;;
		esac
		export LDFLAGS
	fi
	CFLAGS="$CFLAGS -mno-ms-bitfields"
	DEPS="gcc-mingw-w64-base"
	case "$TEST" in
	win64)
		CONFIG="--host=x86_64-w64-mingw32 $CONFIG --enable-dbghelp-backtraces"
		DEPS="gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-x86-64-dev $DEPS"
		CC="x86_64-w64-mingw32-gcc"
		;;
	win32)
		CONFIG="--host=i686-w64-mingw32 $CONFIG"
		DEPS="gcc-mingw-w64-i686 binutils-mingw-w64-i686 mingw-w64-i686-dev $DEPS"
		CC="i686-w64-mingw32-gcc"
		;;
	esac
	;;
android)
	if test "$1" = "build-deps"; then
		build_openssl
	fi
	TARGET=distdir
	;;
macos)
	# this causes a false positive in ip-packet.c since Xcode 8.3
	CFLAGS="$CFLAGS -Wno-address-of-packed-member"
	# use the same options as in the Homebrew Formula
	CONFIG="--disable-defaults --enable-charon --enable-cmd --enable-constraints
			--enable-curl --enable-eap-gtc --enable-eap-identity
			--enable-eap-md5 --enable-eap-mschapv2 --enable-farp --enable-ikev1
			--enable-ikev2 --enable-kernel-libipsec --enable-kernel-pfkey
			--enable-kernel-pfroute --enable-nonce --enable-openssl
			--enable-osx-attr --enable-pem --enable-pgp --enable-pkcs1
			--enable-pkcs8 --enable-pki --enable-pubkey --enable-revocation
			--enable-socket-default --enable-sshkey --enable-stroke
			--enable-swanctl --enable-unity --enable-updown
			--enable-x509 --enable-xauth-generic"
	DEPS="automake autoconf libtool bison gperf pkgconf openssl@1.1 curl"
	BREW_PREFIX=$(brew --prefix)
	export PATH=$BREW_PREFIX/opt/bison/bin:$PATH
	for pkg in openssl@1.1 curl
	do
		PKG_CONFIG_PATH=$BREW_PREFIX/opt/$pkg/lib/pkgconfig:$PKG_CONFIG_PATH
		CPPFLAGS="-I$BREW_PREFIX/opt/$pkg/include $CPPFLAGS"
		LDFLAGS="-L$BREW_PREFIX/opt/$pkg/lib $LDFLAGS"
	done
	export PKG_CONFIG_PATH
	export CPPFLAGS
	export LDFLAGS
	;;
freebsd)
	# use the options of the FreeBSD port (including options), except smp,
	# which requires a patch but is deprecated anyway, only using the builtin
	# printf hooks
	CONFIG="--enable-kernel-pfkey --enable-kernel-pfroute --disable-scripts
			--disable-kernel-netlink --enable-openssl --enable-eap-identity
			--enable-eap-md5 --enable-eap-tls --enable-eap-mschapv2
			--enable-eap-peap --enable-eap-ttls --enable-md4 --enable-blowfish
			--enable-addrblock --enable-whitelist --enable-cmd --enable-curl
			--enable-eap-aka --enable-eap-aka-3gpp2 --enable-eap-dynamic
			--enable-eap-radius --enable-eap-sim --enable-eap-sim-file
			--enable-gcm --enable-ipseckey --enable-kernel-libipsec
			--enable-load-tester --enable-ldap --enable-mediation
			--enable-mysql --enable-sqlite --enable-tpm --enable-tss-tss2
			--enable-unbound --enable-unity --enable-xauth-eap --enable-xauth-pam
			--with-printf-hooks=builtin --enable-attr-sql --enable-sql
			--enable-farp"
	DEPS="git gmp libxml2 mysql80-client sqlite3 unbound ldns tpm2-tss"
	;;
fuzzing)
	CFLAGS="$CFLAGS -DNO_CHECK_MEMWIPE"
	CONFIG="--enable-fuzzing --enable-static --disable-shared --disable-scripts
			--enable-imc-test --enable-tnccs-20"
	# don't run any of the unit tests
	export TESTS_RUNNERS=
	# prepare corpora
	if test -z "$1"; then
		if test -z "$FUZZING_CORPORA"; then
			git clone --depth 1 https://github.com/strongswan/fuzzing-corpora.git fuzzing-corpora
			export FUZZING_CORPORA=$BUILD_DIR/fuzzing-corpora
		fi
		# these are about the same as those on OSS-Fuzz (except for the
		# symbolize options and strip_path_prefix)
		export ASAN_OPTIONS=redzone=16:handle_sigill=1:strict_string_check=1:\
			allocator_release_to_os_interval_ms=500:strict_memcmp=1:detect_container_overflow=1:\
			coverage=0:allocator_may_return_null=1:use_sigaltstack=1:detect_stack_use_after_return=1:\
			alloc_dealloc_mismatch=0:detect_leaks=1:print_scariness=1:max_uar_stack_size_log=16:\
			handle_abort=1:check_malloc_usable_size=0:quarantine_size_mb=10:detect_odr_violation=0:\
			symbolize=1:handle_segv=1:fast_unwind_on_fatal=0:external_symbolizer_path=/usr/bin/llvm-symbolizer-3.5
	fi
	;;
nm)
	DEPS="gnome-common libsecret-1-dev libgtk-3-dev libnm-dev libnma-dev"
	ORIG_SRC_DIR="$SRC_DIR"
	SRC_DIR="$ORIG_SRC_DIR/src/frontends/gnome"
	if [ "$ORIG_SRC_DIR" = "$BUILD_DIR" ]; then
		BUILD_DIR="$SRC_DIR"
	fi
	# don't run ./configure with ./autogen.sh
	export NOCONFIGURE=1
	;;
dist)
	TARGET=distcheck
	;;
apidoc)
	DEPS="doxygen"
	CONFIG="--disable-defaults"
	TARGET=apidoc
	;;
*)
	echo "$0: unknown test $TEST" >&2
	exit 1
	;;
esac

case "$1" in
deps)
	case "$OS_NAME" in
	linux)
		sudo apt-get update -y && \
		sudo apt-get install -y automake autoconf libtool pkgconf bison flex gperf $DEPS
		;;
	alpine)
		apk add --no-cache build-base automake autoconf libtool pkgconfig && \
		apk add --no-cache bison flex gperf tzdata $DEPS
		;;
	macos)
		brew update && \
		brew install $DEPS
		;;
	freebsd)
		pkg install -y automake autoconf libtool pkgconf && \
		pkg install -y bison flex gperf $DEPS
		;;
	esac
	exit $?
	;;
build-deps)
	exit
	;;
*)
	;;
esac

CONFIG="$CONFIG
	--disable-dependency-tracking
	--enable-silent-rules
	--enable-test-vectors
	--enable-monolithic=${MONOLITHIC-no}
	--enable-leak-detective=${LEAK_DETECTIVE-no}"

case "$TEST" in
	alpine|codeql|coverage|freebsd|fuzzing|sonarcloud|win*)
		# don't use AddressSanitizer if it's not available or causes conflicts
		CONFIG="$CONFIG --disable-asan"
		;;
	*)
		if [ "$LEAK_DETECTIVE" != "yes" ]; then
			CONFIG="$CONFIG --enable-asan"
		else
			CONFIG="$CONFIG --disable-asan"
		fi
		;;
esac

cd $SRC_DIR
if [ ! -f ./configure ]; then
	echo "$ ./autogen.sh"
	./autogen.sh || exit $?
fi

cd $BUILD_DIR
echo "$ CC=$CC CFLAGS=\"$CFLAGS\" ./configure $CONFIG"
CC="$CC" CFLAGS="$CFLAGS" $SRC_DIR/configure $CONFIG || exit $?

case "$TEST" in
apidoc)
	exec 2>make.warnings
	;;
*)
	;;
esac

echo "$ make $TARGET"
case "$TEST" in
sonarcloud)
	# without target, coverage is currently not supported anyway because
	# sonarqube only supports gcov, not lcov
	build-wrapper-linux-x86-64 --out-dir $BUILD_WRAPPER_OUT_DIR make -j$(nproc) || exit $?
	;;
*)
	make -j$(nproc) $TARGET || exit $?
	;;
esac

case "$TEST" in
apidoc)
	if test -s make.warnings; then
		cat make.warnings
		exit 1
	fi
	rm make.warnings
	;;
android)
	rm -r strongswan-*
	cd $SRC_DIR/src/frontends/android
	echo "$ ./gradlew build"
	NDK_CCACHE=ccache ./gradlew build --info || exit $?
	;;
*)
	;;
esac

cd $SRC_DIR
# ensure there are no unignored build artifacts (or other changes) in the Git repo
unclean="$(git status --porcelain)"
if test -n "$unclean"; then
	echo "Unignored build artifacts or other changes:"
	echo "$unclean"
	exit 1
fi
