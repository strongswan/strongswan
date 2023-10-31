#!/bin/sh
# Build script for CI

build_botan()
{
	# same revision used in the build recipe of the testing environment
	BOTAN_REV=3.2.0
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
	# disable some larger modules we don't need for the tests
	BOTAN_CONFIG="$BOTAN_CONFIG --disable-modules=pkcs11,tls,x509,xmss
				  --prefix=$DEPS_PREFIX"

	git clone https://github.com/randombit/botan.git $BOTAN_DIR &&
	cd $BOTAN_DIR &&
	git checkout -qf $BOTAN_REV &&
	python ./configure.py --amalgamation $BOTAN_CONFIG &&
	make -j4 libs >/dev/null &&
	sudo make install >/dev/null &&
	sudo ldconfig || exit $?
	cd -
}

build_wolfssl()
{
	WOLFSSL_REV=v5.6.4-stable
	WOLFSSL_DIR=$DEPS_BUILD_DIR/wolfssl

	if test -d "$WOLFSSL_DIR"; then
		return
	fi

	echo "$ build_wolfssl()"

	WOLFSSL_CFLAGS="-DWOLFSSL_PUBLIC_MP -DWOLFSSL_DES_ECB -DHAVE_AES_ECB \
					-DHAVE_ECC_BRAINPOOL -DWOLFSSL_MIN_AUTH_TAG_SZ=8"
	WOLFSSL_CONFIG="--prefix=$DEPS_PREFIX
					--disable-crypttests --disable-examples
					--enable-aesccm --enable-aesctr --enable-camellia
					--enable-curve25519 --enable-curve448 --enable-des3
					--enable-ecccustcurves --enable-ed25519 --enable-ed448
					--enable-keygen --with-max-rsa-bits=8192 --enable-md4
					--enable-rsapss --enable-sha3 --enable-shake256"

	git clone https://github.com/wolfSSL/wolfssl.git $WOLFSSL_DIR &&
	cd $WOLFSSL_DIR &&
	git checkout -qf $WOLFSSL_REV &&
	./autogen.sh &&
	./configure C_EXTRA_FLAGS="$WOLFSSL_CFLAGS" $WOLFSSL_CONFIG &&
	make -j4 >/dev/null &&
	sudo make install >/dev/null &&
	sudo ldconfig || exit $?
	cd -
}

build_tss2()
{
	TSS2_REV=3.2.2
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
	make -j4 >/dev/null &&
	sudo make install >/dev/null &&
	sudo ldconfig || exit $?
	cd -
}

build_openssl()
{
	SSL_REV=3.1.1
	SSL_PKG=openssl-$SSL_REV
	SSL_DIR=$DEPS_BUILD_DIR/$SSL_PKG
	SSL_SRC=https://www.openssl.org/source/$SSL_PKG.tar.gz
	SSL_INS=$DEPS_PREFIX/ssl
	SSL_OPT="-d shared no-dtls no-ssl3 no-zlib no-idea no-psk no-srp
			 no-tests enable-rfc3779 enable-ec_nistp_64_gcc_128"

	if test -d "$SSL_DIR"; then
		return
	fi

	# insist on compiling with gcc and debug information as symbols are otherwise not found
	if test "$LEAK_DETECTIVE" = "yes"; then
		SSL_OPT="$SSL_OPT CC=gcc -d"
	fi

	echo "$ build_openssl()"

	curl -L $SSL_SRC | tar xz -C $DEPS_BUILD_DIR || exit $?

	if [ "$TEST" = "android" ]; then
		OPENSSL_SRC=${SSL_DIR} \
		NO_DOCKER=1 src/frontends/android/openssl/build.sh || exit $?
	else
		cd $SSL_DIR &&
		./config --prefix=$SSL_INS --openssldir=$SSL_INS --libdir=lib $SSL_OPT &&
		make -j4 >/dev/null &&
		sudo make install_sw >/dev/null &&
		sudo ldconfig || exit $?
		cd -
	fi
}

use_custom_openssl()
{
	CFLAGS="$CFLAGS -I$DEPS_PREFIX/ssl/include"
	export LDFLAGS="$LDFLAGS -L$DEPS_PREFIX/ssl/lib"
	export LD_LIBRARY_PATH="$DEPS_PREFIX/ssl/lib:$LD_LIBRARY_PATH"
	if test "$1" = "build-deps"; then
		build_openssl
	fi
}

system_uses_openssl3()
{
	pkg-config --atleast-version=3.0.0 libcrypto
	return $?
}

prepare_system_openssl()
{
	# On systems that ship OpenSSL 3 (e.g. Ubuntu 22.04), we require debug
	# symbols to whitelist leaks
	if test "$1" = "deps"; then
		echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted
			deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted
			deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted" | \
			sudo tee -a /etc/apt/sources.list.d/ddebs.list
		sudo apt-get install -qq ubuntu-dbgsym-keyring
		DEPS="$DEPS libssl3-dbgsym"
	fi
	if test "$LEAK_DETECTIVE" = "yes"; then
		# make sure we can properly whitelist functions with leak detective
		DEPS="$DEPS binutils-dev"
		CONFIG="$CONFIG --enable-bfd-backtraces"
	else
		# with ASan we have to use the (extremely) slow stack unwind as the
		# shipped version of the library is built with -fomit-frame-pointer
		export ASAN_OPTIONS=fast_unwind_on_malloc=0
	fi
}

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
	;;
openssl*)
	CONFIG="--disable-defaults --enable-pki --enable-openssl --enable-pem"
	export TESTS_PLUGINS="test-vectors openssl! pem"
	DEPS="libssl-dev"
	if test "$TEST" = "openssl-3"; then
		DEPS=""
		use_custom_openssl $1
	elif system_uses_openssl3; then
		prepare_system_openssl $1
	fi
	;;
gcrypt)
	CONFIG="--disable-defaults --enable-pki --enable-gcrypt --enable-random --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-gcm --enable-hmac --enable-kdf -enable-curve25519 --enable-x509 --enable-constraints"
	export TESTS_PLUGINS="test-vectors gcrypt! random pem pkcs1 pkcs8 gcm hmac kdf curve25519 x509 constraints"
	DEPS="libgcrypt20-dev"
	;;
botan)
	CONFIG="--disable-defaults --enable-pki --enable-botan --enable-pem --enable-hmac --enable-x509 --enable-constraints"
	export TESTS_PLUGINS="test-vectors botan! pem hmac x509 constraints"
	DEPS=""
	if test "$1" = "build-deps"; then
		build_botan
	fi
	;;
wolfssl)
	CONFIG="--disable-defaults --enable-pki --enable-wolfssl --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-x509 --enable-constraints"
	export TESTS_PLUGINS="test-vectors wolfssl! pem pkcs1 pkcs8 x509 constraints"
	# build with custom options to enable all the features the plugin supports
	DEPS=""
	if test "$1" = "build-deps"; then
		build_wolfssl
	fi
	;;
printf-builtin)
	CONFIG="--with-printf-hooks=builtin"
	;;
all|codeql|coverage|sonarcloud|no-dbg)
	if [ "$TEST" = "sonarcloud" ]; then
		if [ -z "$SONAR_PROJECT" -o -z "$SONAR_ORGANIZATION" -o -z "$SONAR_TOKEN" ]; then
			echo "The SONAR_PROJECT, SONAR_ORGANIZATION and SONAR_TOKEN" \
				 "environment variables are required to run this test"
			exit 1
		fi
	fi
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
			--disable-osx-attr --disable-tkm --disable-uci
			--disable-unwind-backtraces
			--disable-svc --disable-dbghelp-backtraces --disable-socket-win
			--disable-kernel-wfp --disable-kernel-iph --disable-winhttp
			--disable-python-eggs-install"
	# not enabled on the build server
	CONFIG="$CONFIG --disable-af-alg"
	# unable to build Botan on Ubuntu 20.04
	if [ "$ID" = "ubuntu" -a "$VERSION_ID" = "20.04" ]; then
		CONFIG="$CONFIG --disable-botan"
	fi
	if test "$TEST" != "coverage"; then
		CONFIG="$CONFIG --disable-coverage"
	else
		# not actually required but configure checks for it
		DEPS="$DEPS lcov"
	fi
	DEPS="$DEPS libcurl4-gnutls-dev libsoup2.4-dev libunbound-dev libldns-dev
		  libmysqlclient-dev libsqlite3-dev clearsilver-dev libfcgi-dev
		  libldap2-dev libpcsclite-dev libpam0g-dev binutils-dev libnm-dev
		  libgcrypt20-dev libjson-c-dev python3-pip libtspi-dev libsystemd-dev
		  libselinux1-dev libiptc-dev"
	PYDEPS="tox"
	if test "$1" = "build-deps"; then
		if [ "$ID" = "ubuntu" -a "$VERSION_ID" != "20.04" ]; then
			build_botan
		fi
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
		case "$IMG" in
		2015|2017)
			# old OpenSSL versions don't provide HKDF
			CONFIG="$CONFIG --enable-kdf"
			;;
		esac

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
	DEPS="automake autoconf libtool bison gettext pkg-config openssl@1.1 curl"
	BREW_PREFIX=$(brew --prefix)
	export PATH=$BREW_PREFIX/opt/bison/bin:$PATH
	export ACLOCAL_PATH=$BREW_PREFIX/opt/gettext/share/aclocal:$ACLOCAL_PATH
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
	cd src/frontends/gnome
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
		sudo apt-get update -qq && \
		sudo apt-get install -qq bison flex gperf gettext $DEPS
		;;
	macos)
		brew update && \
		brew install $DEPS
		;;
	freebsd)
		pkg install -y automake autoconf libtool pkgconf && \
		pkg install -y bison flex gperf gettext $DEPS
		;;
	esac
	exit $?
	;;
pydeps)
	test -z "$PYDEPS" || pip3 -q install --user $PYDEPS
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
	codeql|coverage|freebsd|fuzzing|sonarcloud|win*)
		# don't use AddressSanitizer if it's not available or causes conflicts
		CONFIG="$CONFIG --disable-asan"
		;;
	*)
		if [ "$LEAK_DETECTIVE" != "yes" ]; then
			CONFIG="$CONFIG --enable-asan"
		fi
		;;
esac

echo "$ ./autogen.sh"
./autogen.sh || exit $?
echo "$ CC=$CC CFLAGS=\"$CFLAGS\" ./configure $CONFIG"
CC="$CC" CFLAGS="$CFLAGS" ./configure $CONFIG || exit $?

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
	build-wrapper-linux-x86-64 --out-dir bw-output make -j4 || exit $?
	;;
*)
	make -j4 $TARGET || exit $?
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
sonarcloud)
	sonar-scanner \
		-Dsonar.host.url=https://sonarcloud.io \
		-Dsonar.projectKey=${SONAR_PROJECT} \
		-Dsonar.organization=${SONAR_ORGANIZATION} \
		-Dsonar.login=${SONAR_TOKEN} \
		-Dsonar.projectVersion=$(git describe --exclude 'android-*')+${BUILD_NUMBER} \
		-Dsonar.sources=. \
		-Dsonar.cfamily.threads=2 \
		-Dsonar.cfamily.analysisCache.mode=fs \
		-Dsonar.cfamily.analysisCache.path=$HOME/.sonar-cache \
		-Dsonar.cfamily.build-wrapper-output=bw-output || exit $?
	rm -r bw-output .scannerwork
	;;
android)
	rm -r strongswan-*
	cd src/frontends/android
	echo "$ ./gradlew build"
	NDK_CCACHE=ccache ./gradlew build --info || exit $?
	;;
*)
	;;
esac

# ensure there are no unignored build artifacts (or other changes) in the Git repo
unclean="$(git status --porcelain)"
if test -n "$unclean"; then
	echo "Unignored build artifacts or other changes:"
	echo "$unclean"
	exit 1
fi
