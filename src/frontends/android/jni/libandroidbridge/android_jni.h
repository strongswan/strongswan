/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup android_jni android_jni
 * @{ @ingroup libandroidbridge
 */

#ifndef ANDROID_JNI_H_
#define ANDROID_JNI_H_

#include <jni.h>

#define JNI_PACKAGE org_strongswan_android
#define JNI_PACKAGE_STRING "org/strongswan/android"

#define JNI_METHOD_PP(pack, klass, name, ret, ...) \
	ret Java_##pack##_##klass##_##name(JNIEnv *env, jobject this, ##__VA_ARGS__)

#define JNI_METHOD_P(pack, klass, name, ret, ...) \
	JNI_METHOD_PP(pack, klass, name, ret, ##__VA_ARGS__)

#define JNI_METHOD(klass, name, ret, ...) \
	JNI_METHOD_P(JNI_PACKAGE, klass, name, ret, ##__VA_ARGS__)

/**
 * Java classes
 * Initialized in JNI_OnLoad()
 */
extern jclass *android_charonvpnservice_class;

#endif /** ANDROID_JNI_H_ @}*/
