#!/bin/bash
#
# Compile static versions of OpenSSL's libcrypto for use with strongSwan's
# Android app.
#
# Copies archives and header files to $OUT_DIR.

set -e

export PATH=${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
# necessary for OpenSSL 1.1.1
export ANDROID_NDK_HOME=${ANDROID_NDK_ROOT}

# automatically determine the ABIs supported by the NDK
: ${ABIS=$(jq -r 'keys | join(" ")' ${ANDROID_NDK_ROOT}/meta/abis.json)}

# this should match APP_PLATFORM
: ${MIN_SDK=21}

for ABI in ${ABIS}
do

echo "## Building OpenSSL's libcrypto for ${ABI}"

case ${ABI} in
armeabi-v7a)
	OPTIONS="android-arm"
	;;
arm64-v8a)
	OPTIONS="android-arm64"
	;;
x86)
	OPTIONS="android-x86"
	;;
x86_64)
	OPTIONS="android-x86_64"
	;;
esac

OPTIONS="${OPTIONS} \
  no-shared no-ct no-cast no-comp no-dgram no-dsa no-gost no-idea \
  no-rmd160 no-seed no-sm2 no-sm3 no-sm4 no-sock no-srp no-srtp \
  no-err no-engine no-dso no-hw no-stdio no-ui-console \
  -fPIC -DOPENSSL_PIC \
  -ffast-math -O3 -funroll-loops -Wno-macro-redefined \
  -D__ANDROID_API__=${MIN_SDK} \
  "

make distclean >/dev/null || true

./Configure ${OPTIONS}
make -j $(nproc) build_generated >/dev/null
make -j $(nproc) libcrypto.a >/dev/null

mkdir -p ${OUT_DIR}/${ABI}
cp libcrypto.a ${OUT_DIR}/${ABI}

done

# The only difference between ABIs is the config header (e.g. configuration.h
# for OpenSSL 3.0), which does define the size of BN_ULONG in bn.h.
# However, the only function we use that depends on it is BN_set_word() when
# generating RSA private keys, which isn't used in the Android app.
cp -R include/ ${OUT_DIR}
