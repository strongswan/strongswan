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

#include "android_jni.h"

#include <library.h>

/**
 * JVM
 */
static JavaVM *android_jvm;

jclass *android_charonvpnservice_class;

/**
 * Called when this library is loaded by the JVM
 */
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;

	android_jvm = vm;

	if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK)
	{
		return -1;
	}

	android_charonvpnservice_class =
				(*env)->NewGlobalRef(env, (*env)->FindClass(env,
						JNI_PACKAGE_STRING "/CharonVpnService"));

	return JNI_VERSION_1_6;
}

