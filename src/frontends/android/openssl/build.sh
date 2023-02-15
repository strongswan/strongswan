#!/bin/bash
#
# Build OpenSSL's libcrypto for use in strongSwan's Android app.  Requires
# passing the path to the Android NDK as well as that to the OpenSSL sources,
# for instance:
#
#   ANDROID_NDK_ROOT=~/android-ndk OPENSSL_SRC=~/openssl ./build.sh
#
# The files are written to the jni/openssl directory of the app, by default, but
# that can be changed via $OUT variable.
#
# Setting $NO_DOCKER disables the use of Docker (requires the necessary build
# tools on the system), otherwise, setting $TAG allows using a custom tag for
# the Docker image.
#

set -e

if [ -z "${ANDROID_NDK_ROOT}" ]; then
	echo "ANDROID_NDK_ROOT is not set"
	exit 1
elif [ ! -d "${ANDROID_NDK_ROOT}" ]; then
	echo "ANDROID_NDK_ROOT=${ANDROID_NDK_ROOT} is not a directory"
	exit 1
fi

if [ -z "${OPENSSL_SRC}" ]; then
	echo "OPENSSL_SRC is not set"
	exit 1
elif [ ! -d "${OPENSSL_SRC}" ]; then
	echo "OPENSSL_SRC=${OPENSSL_SRC} is not a directory"
	exit 1
fi

: ${TAG=strongswan-android-openssl-builder}

DIR=$(dirname `readlink -f $0`)
: ${OUT=$DIR/../app/src/main/jni/openssl}
mkdir -p $OUT

if [ -z "${NO_DOCKER}" ]; then
	docker build -t ${TAG} ${DIR}
	docker run --rm -ti \
		-u $(id -u ${USER}):$(id -g ${USER}) \
		-v ${ANDROID_NDK_ROOT}:/ndk \
		-v ${OPENSSL_SRC}:/src \
		-v ${OUT}:/out \
		${TAG}
else
	pushd $OPENSSL_SRC
	OUT_DIR=${OUT} $DIR/compile.sh
	popd
fi

if [ ! -f "${OUT}/Android.mk" ]; then
	echo "## Creating Android.mk for OpenSSL's libcrypto"
	cat << EOF > ${OUT}/Android.mk
LOCAL_PATH := \$(call my-dir)
include \$(CLEAR_VARS)
LOCAL_MODULE := libcrypto_static
LOCAL_SRC_FILES := \$(TARGET_ARCH_ABI)/libcrypto.a
LOCAL_EXPORT_C_INCLUDES := \$(LOCAL_PATH)/include
include \$(PREBUILT_STATIC_LIBRARY)
EOF
fi
