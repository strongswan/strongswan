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
#include <library.h>

#define JNI_PACKAGE org_strongswan_android_logic
#define JNI_PACKAGE_STRING "org/strongswan/android/logic"

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
extern jclass *android_charonvpnservice_builder_class;

/**
 * Attach the current thread to the JVM
 *
 * As local JNI references are not freed until the thread detaches
 * androidjni_detach_thread() should be called as soon as possible.
 * If it is not called a thread-local destructor ensures that the
 * thread is at least detached as soon as it terminates.
 *
 * @param env		JNIEnv
 */
void androidjni_attach_thread(JNIEnv **env);

/**
 * Detach the current thread from the JVM
 *
 * Call this as soon as possible to ensure that local JNI references are freed.
 */
void androidjni_detach_thread();

/**
 * Handle exceptions thrown by a JNI call
 *
 * @param env		JNIEnv
 * @return			TRUE if an exception was thrown
 */
static inline bool androidjni_exception_occurred(JNIEnv *env)
{
	if ((*env)->ExceptionOccurred(env))
	{	/* clear any exception, otherwise the VM is terminated */
		(*env)->ExceptionDescribe(env);
		(*env)->ExceptionClear(env);
		return TRUE;
	}
	return FALSE;
}

#endif /** ANDROID_JNI_H_ @}*/
