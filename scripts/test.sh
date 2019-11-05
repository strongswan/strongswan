#!/bin/sh
# Build script for CI

build_botan()
{
	# same revision used in the build recipe of the testing environment
	BOTAN_REV=2.18.0
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
	WOLFSSL_REV=v4.8.0-stable
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
					--enable-keygen --enable-md4 --enable-rsapss --enable-sha3
					--enable-shake256"

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
	TSS2_REV=2.4.3
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

CFLAGS="-g -O2 -Wall -Wno-format -Wno-format-security -Wno-pointer-sign -Werror"

case "$TEST" in
default)
	# should be the default, but lets make sure
	CONFIG="--with-printf-hooks=glibc"
	;;
openssl*)
	CONFIG="--disable-defaults --enable-pki --enable-openssl --enable-pem"
	export TESTS_PLUGINS="test-vectors pem openssl!"
	DEPS="libssl-dev"
	;;
gcrypt)
	CONFIG="--disable-defaults --enable-pki --enable-gcrypt --enable-pkcs1"
	export TESTS_PLUGINS="test-vectors pkcs1 gcrypt!"
	if [ "$ID" = "ubuntu" -a "$VERSION_ID" = "20.04" ]; then
		DEPS="libgcrypt20-dev"
	else
		DEPS="libgcrypt11-dev"
	fi
	;;
botan)
	CONFIG="--disable-defaults --enable-pki --enable-botan --enable-pem"
	export TESTS_PLUGINS="test-vectors pem botan!"
	DEPS=""
	if test "$1" = "build-deps"; then
		build_botan
	fi
	;;
wolfssl)
	CONFIG="--disable-defaults --enable-pki --enable-wolfssl --enable-pem"
	export TESTS_PLUGINS="test-vectors pem wolfssl!"
	# build with custom options to enable all the features the plugin supports
	DEPS=""
	if test "$1" = "build-deps"; then
		build_wolfssl
	fi
	;;
printf-builtin)
	CONFIG="--with-printf-hooks=builtin"
	;;
all|coverage|sonarcloud)
	if [ "$TEST" = "sonarcloud" ]; then
		if [ -z "$SONAR_PROJECT" -o -z "$SONAR_ORGANIZATION" -o -z "$SONAR_TOKEN" ]; then
			echo "The SONAR_PROJECT, SONAR_ORGANIZATION and SONAR_TOKEN" \
				 "environment variables are required to run this test"
			exit 1
		fi
	fi
	CONFIG="--enable-all --disable-android-dns --disable-android-log
			--disable-kernel-pfroute --disable-keychain
			--disable-lock-profiler --disable-padlock --disable-fuzzing
			--disable-osx-attr --disable-tkm --disable-uci
			--disable-oqs --disable-unwind-backtraces
			--disable-svc --disable-dbghelp-backtraces --disable-socket-win
			--disable-kernel-wfp --disable-kernel-iph --disable-winhttp
			--disable-python-eggs-install"
	# not enabled on the build server
	CONFIG="$CONFIG --disable-af-alg"
	if test "$TEST" != "coverage"; then
		CONFIG="$CONFIG --disable-coverage"
	else
		# not actually required but configure checks for it
		DEPS="$DEPS lcov"
	fi
	DEPS="$DEPS libcurl4-gnutls-dev libsoup2.4-dev libunbound-dev libldns-dev
		  libmysqlclient-dev libsqlite3-dev clearsilver-dev libfcgi-dev
		  libldap2-dev libpcsclite-dev libpam0g-dev binutils-dev libnm-dev
		  libgcrypt20-dev libjson-c-dev python3-pip libtspi-dev libsystemd-dev"
	if [ "$ID" = "ubuntu" -a "$VERSION_ID" = "20.04" ]; then
		DEPS="$DEPS libiptc-dev"
	else
		DEPS="$DEPS iptables-dev python3-setuptools"
	fi
	PYDEPS="tox"
	if test "$1" = "build-deps"; then
		build_botan
		build_wolfssl
		build_tss2
	fi
	;;
win*)
	CONFIG="--disable-defaults --enable-svc --enable-ikev2
			--enable-ikev1 --enable-static --enable-test-vectors --enable-nonce
			--enable-constraints --enable-revocation --enable-pem --enable-pkcs1
			--enable-pkcs8 --enable-x509 --enable-pubkey --enable-acert
			--enable-eap-tnc --enable-eap-ttls --enable-eap-identity
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
		LDFLAGS="-L$OPENSSL_DIR"
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
	if test "$1" = "deps"; then
		git clone git://git.strongswan.org/android-ndk-boringssl.git -b ndk-static \
			src/frontends/android/app/src/main/jni/openssl
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
			--enable-scepclient --enable-socket-default --enable-sshkey
			--enable-stroke --enable-swanctl --enable-unity --enable-updown
			--enable-x509 --enable-xauth-generic"
	DEPS="automake autoconf libtool bison gettext openssl curl"
	BREW_PREFIX=$(brew --prefix)
	export PATH=$BREW_PREFIX/opt/bison/bin:$PATH
	export ACLOCAL_PATH=$BREW_PREFIX/opt/gettext/share/aclocal:$ACLOCAL_PATH
	for pkg in openssl curl
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
	DEPS="git gmp openldap-client libxml2 mysql80-client sqlite3 unbound ldns tpm2-tss"
	export GPERF=/usr/local/bin/gperf
	export LEX=/usr/local/bin/flex
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
nm|nm-no-glib)
	DEPS="gnome-common libsecret-1-dev libgtk-3-dev libnm-dev libnma-dev"
	if test "$TEST" = "nm"; then
		DEPS="$DEPS libnm-glib-vpn-dev libnm-gtk-dev"
	else
		CONFIG="$CONFIG --without-libnm-glib"
	fi
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
lgtm)
	if [ -z "$LGTM_PROJECT" -o -z "$LGTM_TOKEN" ]; then
		echo "The LGTM_PROJECT and LGTM_TOKEN environment variables" \
			 "are required to run this test"
		exit 0
	fi
	DEPS="jq"
	if test -z "$1"; then
		base=$COMMIT_BASE
		# after rebases or for new/duplicate branches, the passed base commit
		# ID might not be valid
		git rev-parse -q --verify $base^{commit}
		if [ $? != 0 ]; then
			# this will always compare against master, while via base we
			# otherwise only contains "new" commits
			base=$(git merge-base origin/master ${COMMIT_ID})
		fi
		base=$(git rev-parse $base)

		echo "Starting code review for $COMMIT_ID (base $base) on lgtm.com"
		git diff --binary $base > lgtm.patch || exit $?
		curl -s -X POST --data-binary @lgtm.patch \
			"https://lgtm.com/api/v1.0/codereviews/${LGTM_PROJECT}?base=${base}&external-id=${BUILD_NUMBER}" \
			-H 'Content-Type: application/octet-stream' \
			-H 'Accept: application/json' \
			-H "Authorization: Bearer ${LGTM_TOKEN}" > lgtm.res || exit $?
		lgtm_check_url=$(jq -r '."task-result-url"' lgtm.res)
		if [ -z "$lgtm_check_url" -o "$lgtm_check_url" = "null" ]; then
			cat lgtm.res
			exit 1
		fi
		lgtm_url=$(jq -r '."task-result"."results-url"' lgtm.res)
		echo "Progress and full results: ${lgtm_url}"

		echo -n "Waiting for completion: "
		lgtm_status=pending
		while [ "$lgtm_status" = "pending" ]; do
			sleep 15
			curl -s -X GET "${lgtm_check_url}" \
				-H 'Accept: application/json' \
				-H "Authorization: Bearer ${LGTM_TOKEN}" > lgtm.res
			if [ $? != 0 ]; then
				echo -n "-"
				continue
			fi
			echo -n "."
			lgtm_status=$(jq -r '.status' lgtm.res)
		done
		echo ""

		if [ "$lgtm_status" != "success" ]; then
			lgtm_message=$(jq -r '.["status-message"]' lgtm.res)
			echo "Code review failed: ${lgtm_message}"
			exit 1
		fi
		lgtm_new=$(jq -r '.languages[].new' lgtm.res | awk '{t+=$1} END {print t}')
		lgtm_fixed=$(jq -r '.languages[].fixed' lgtm.res | awk '{t+=$1} END {print t}')
		echo -n "Code review complete: "
		printf "%b\n" "\e[1;31m${lgtm_new}\e[0m new alerts, \e[1;32m${lgtm_fixed}\e[0m fixed"
		exit $lgtm_new
	fi
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
		-Dsonar.cfamily.cache.enabled=true \
		-Dsonar.cfamily.cache.path=$HOME/.sonar-cache \
		-Dsonar.cfamily.build-wrapper-output=bw-output || exit $?
	rm -r bw-output .scannerwork
	;;
android)
	rm -r strongswan-*
	cd src/frontends/android
	echo "$ ./gradlew build"
	NDK_CCACHE=ccache ./gradlew build || exit $?
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
