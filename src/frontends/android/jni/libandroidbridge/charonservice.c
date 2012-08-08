/*
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Copyright (C) 2012 Tobias Brunner
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

#include <signal.h>
#include <string.h>
#include <android/log.h>

#include "charonservice.h"
#include "android_jni.h"
#include "backend/android_attr.h"
#include "backend/android_creds.h"
#include "backend/android_service.h"
#include "kernel/android_ipsec.h"
#include "kernel/android_net.h"

#include <daemon.h>
#include <hydra.h>
#include <ipsec.h>
#include <library.h>
#include <threading/thread.h>

#define ANDROID_DEBUG_LEVEL 1

typedef struct private_charonservice_t private_charonservice_t;

/**
 * private data of charonservice
 */
struct private_charonservice_t {

	/**
	 * public interface
	 */
	charonservice_t public;

	/**
	 * android_attr instance
	 */
	android_attr_t *attr;

	/**
	 * android_creds instance
	 */
	android_creds_t *creds;

	/**
	 * android_service instance
	 */
	android_service_t *service;

	/**
	 * VpnService builder (accessed via JNI)
	 */
	vpnservice_builder_t *builder;

	/**
	 * CharonVpnService reference
	 */
	jobject vpn_service;
};

/**
 * Single instance of charonservice_t.
 */
charonservice_t *charonservice;

/**
 * hook in library for debugging messages
 */
extern void (*dbg)(debug_t group, level_t level, char *fmt, ...);

/**
 * Logging hook for library logs, using android specific logging
 */
static void dbg_android(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	if (level <= ANDROID_DEBUG_LEVEL)
	{
		char sgroup[16], buffer[8192];
		char *current = buffer, *next;

		snprintf(sgroup, sizeof(sgroup), "%N", debug_names, group);
		va_start(args, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);
		while (current)
		{	/* log each line separately */
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			__android_log_print(ANDROID_LOG_INFO, "charon", "00[%s] %s\n",
								sgroup, current);
			current = next;
		}
	}
}

METHOD(charonservice_t, update_status, bool,
	private_charonservice_t *this, android_vpn_state_t code)
{
	JNIEnv *env;
	jmethodID method_id;
	bool success = FALSE;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_class,
									"updateStatus", "(I)V");
	if (!method_id)
	{
		goto failed;
	}
	(*env)->CallVoidMethod(env, this->vpn_service, method_id, (jint)code);
	success = !androidjni_exception_occurred(env);

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return success;
}

METHOD(charonservice_t, bypass_socket, bool,
	private_charonservice_t *this, int fd, int family)
{
	JNIEnv *env;
	jmethodID method_id;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_class,
									"protect", "(I)Z");
	if (!method_id)
	{
		goto failed;
	}
	if (!(*env)->CallBooleanMethod(env, this->vpn_service, method_id, fd))
	{
		DBG1(DBG_CFG, "VpnService.protect() failed");
		goto failed;
	}
	androidjni_detach_thread();
	return TRUE;

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return FALSE;
}

METHOD(charonservice_t, get_trusted_certificates, linked_list_t*,
	private_charonservice_t *this)
{
	JNIEnv *env;
	jmethodID method_id;
	jobjectArray jcerts;
	linked_list_t *list;
	jsize i;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env,
						android_charonvpnservice_class,
						"getTrustedCertificates", "(Ljava/lang/String;)[[B");
	if (!method_id)
	{
		goto failed;
	}
	jcerts = (*env)->CallObjectMethod(env, this->vpn_service, method_id, NULL);
	if (!jcerts)
	{
		goto failed;
	}
	list = linked_list_create();
	for (i = 0; i < (*env)->GetArrayLength(env, jcerts); ++i)
	{
		chunk_t *ca_cert;
		jbyteArray jcert;

		ca_cert = malloc_thing(chunk_t);
		list->insert_last(list, ca_cert);

		jcert = (*env)->GetObjectArrayElement(env, jcerts, i);
		*ca_cert = chunk_alloc((*env)->GetArrayLength(env, jcert));
		(*env)->GetByteArrayRegion(env, jcert, 0, ca_cert->len, ca_cert->ptr);
		(*env)->DeleteLocalRef(env, jcert);
	}
	(*env)->DeleteLocalRef(env, jcerts);
	androidjni_detach_thread();
	return list;

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return NULL;
}

METHOD(charonservice_t, get_vpnservice_builder, vpnservice_builder_t*,
	private_charonservice_t *this)
{
	return this->builder;
}

/**
 * Initiate a new connection
 *
 * @param local				local ip address (gets owned)
 * @param gateway			gateway address (gets owned)
 * @param username			username (gets owned)
 * @param password			password (gets owned)
 */
static void initiate(char *local, char *gateway, char *username, char *password)
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;

	this->creds->clear(this->creds);
	this->creds->add_username_password(this->creds, username, password);
	memwipe(password, strlen(password));
	free(password);

	DESTROY_IF(this->service);
	this->service = android_service_create(local, gateway, username);
}

/**
 * Initialize/deinitialize Android backend
 */
static bool charonservice_register(void *plugin, plugin_feature_t *feature,
								   bool reg, void *data)
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;
	if (reg)
	{
		lib->credmgr->add_set(lib->credmgr, &this->creds->set);
		hydra->attributes->add_handler(hydra->attributes,
									   &this->attr->handler);
	}
	else
	{
		lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
		hydra->attributes->remove_handler(hydra->attributes,
										  &this->attr->handler);
		if (this->service)
		{
			this->service->destroy(this->service);
			this->service = NULL;
		}
	}
	return TRUE;
}

/**
 * Initialize the charonservice object
 */
static void charonservice_init(JNIEnv *env, jobject service, jobject builder)
{
	private_charonservice_t *this;
	static plugin_feature_t features[] = {
		PLUGIN_CALLBACK(kernel_net_register, kernel_android_net_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-net"),
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_android_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK((plugin_feature_callback_t)charonservice_register, NULL),
			PLUGIN_PROVIDE(CUSTOM, "Android backend"),
				PLUGIN_DEPENDS(CUSTOM, "libcharon"),
	};

	INIT(this,
		.public = {
			.update_status = _update_status,
			.bypass_socket = _bypass_socket,
			.get_trusted_certificates = _get_trusted_certificates,
			.get_vpnservice_builder = _get_vpnservice_builder,
		},
		.attr = android_attr_create(),
		.creds = android_creds_create(),
		.builder = vpnservice_builder_create(builder),
		.vpn_service = (*env)->NewGlobalRef(env, service),
	);
	charonservice = &this->public;

	lib->plugins->add_static_features(lib->plugins, "androidbridge", features,
									  countof(features), TRUE);

	lib->settings->set_int(lib->settings,
					"charon.plugins.android_log.loglevel", ANDROID_DEBUG_LEVEL);
}

/**
 * Deinitialize the charonservice object
 */
static void charonservice_deinit(JNIEnv *env)
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;

	this->builder->destroy(this->builder);
	this->creds->destroy(this->creds);
	this->attr->destroy(this->attr);
	(*env)->DeleteGlobalRef(env, this->vpn_service);
	free(this);
	charonservice = NULL;
}

/**
 * Handle SIGSEGV/SIGILL signals raised by threads
 */
static void segv_handler(int signal)
{
	dbg_android(DBG_DMN, 1, "thread %u received %d", thread_current_id(),
				signal);
	exit(1);
}

/**
 * Initialize charon and the libraries via JNI
 */
JNI_METHOD(CharonVpnService, initializeCharon, void,
	jobject builder)
{
	struct sigaction action;

	/* logging for library during initialization, as we have no bus yet */
	dbg = dbg_android;

	/* initialize library */
	if (!library_init(NULL))
	{
		library_deinit();
		return;
	}

	if (!libhydra_init("charon"))
	{
		libhydra_deinit();
		library_deinit();
		return;
	}

	if (!libipsec_init())
	{
		libipsec_deinit();
		libhydra_deinit();
		library_deinit();
		return;
	}

	charonservice_init(env, this, builder);

	if (!libcharon_init("charon") ||
		!charon->initialize(charon, PLUGINS))
	{
		libcharon_deinit();
		charonservice_deinit(env);
		libipsec_deinit();
		libhydra_deinit();
		library_deinit();
		return;
	}

	/* add handler for SEGV and ILL etc. */
	action.sa_handler = segv_handler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);

	/* start daemon (i.e. the threads in the thread-pool) */
	charon->start(charon);
}

/**
 * Deinitialize charon and all libraries
 */
JNI_METHOD(CharonVpnService, deinitializeCharon, void)
{
	libcharon_deinit();
	charonservice_deinit(env);
	libipsec_deinit();
	libhydra_deinit();
	library_deinit();
}

/**
 * Convert a Java string to a C string.  Memory is allocated.
 */
static inline char *convert_jstring(JNIEnv *env, jstring jstr)
{
	char *str;
	jsize len;

	len = (*env)->GetStringUTFLength(env, jstr);
	str = malloc(len + 1);
	(*env)->GetStringUTFRegion(env, jstr, 0, len, str);
	str[len] = '\0';
	return str;
}

/**
 * Initiate SA
 */
JNI_METHOD(CharonVpnService, initiate, void,
	jstring jlocal_address, jstring jgateway, jstring jusername,
	jstring jpassword)
{
	char *local_address, *gateway, *username, *password;

	local_address = convert_jstring(env, jlocal_address);
	gateway = convert_jstring(env, jgateway);
	username = convert_jstring(env, jusername);
	password = convert_jstring(env, jpassword);

	initiate(local_address, gateway, username, password);
}
