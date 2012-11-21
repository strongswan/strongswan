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
#include <sys/utsname.h>
#include <android/log.h>
#include <errno.h>

#include "charonservice.h"
#include "android_jni.h"
#include "backend/android_attr.h"
#include "backend/android_creds.h"
#include "backend/android_private_key.h"
#include "backend/android_service.h"
#include "kernel/android_ipsec.h"
#include "kernel/android_net.h"

#include <daemon.h>
#include <hydra.h>
#include <ipsec.h>
#include <library.h>
#include <threading/thread.h>

#define ANDROID_DEBUG_LEVEL 1
#define ANDROID_RETRASNMIT_TRIES 3
#define ANDROID_RETRANSMIT_TIMEOUT 2.0
#define ANDROID_RETRANSMIT_BASE 1.4

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
	 * NetworkManager instance (accessed via JNI)
	 */
	network_manager_t *network_manager;

	/**
	 * CharonVpnService reference
	 */
	jobject vpn_service;

	/**
	 * Sockets that were bypassed and we keep track for
	 */
	linked_list_t *sockets;
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

/**
 * Bypass a single socket
 */
static bool bypass_single_socket(intptr_t fd, private_charonservice_t *this)
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
		DBG2(DBG_KNL, "VpnService.protect() failed");
		goto failed;
	}
	androidjni_detach_thread();
	return TRUE;

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return FALSE;
}

METHOD(charonservice_t, bypass_socket, bool,
	private_charonservice_t *this, int fd, int family)
{
	if (fd >= 0)
	{
		this->sockets->insert_last(this->sockets, (void*)(intptr_t)fd);
		return bypass_single_socket((intptr_t)fd, this);
	}
	this->sockets->invoke_function(this->sockets, (void*)bypass_single_socket,
								   this);
	return TRUE;
}

/**
 * Converts the given Java array of byte arrays (byte[][]) to a linked list
 * of chunk_t objects.
 */
static linked_list_t *convert_array_of_byte_arrays(JNIEnv *env,
												   jobjectArray jarray)
{
	linked_list_t *list;
	jsize i;

	list = linked_list_create();
	for (i = 0; i < (*env)->GetArrayLength(env, jarray); ++i)
	{
		chunk_t *chunk;
		jbyteArray jbytearray;

		chunk = malloc_thing(chunk_t);
		list->insert_last(list, chunk);

		jbytearray = (*env)->GetObjectArrayElement(env, jarray, i);
		*chunk = chunk_alloc((*env)->GetArrayLength(env, jbytearray));
		(*env)->GetByteArrayRegion(env, jbytearray, 0, chunk->len, chunk->ptr);
		(*env)->DeleteLocalRef(env, jbytearray);
	}
	return list;
}

METHOD(charonservice_t, get_trusted_certificates, linked_list_t*,
	private_charonservice_t *this)
{
	JNIEnv *env;
	jmethodID method_id;
	jobjectArray jcerts;
	linked_list_t *list;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env,
						android_charonvpnservice_class,
						"getTrustedCertificates", "(Ljava/lang/String;)[[B");
	if (!method_id)
	{
		goto failed;
	}
	jcerts = (*env)->CallObjectMethod(env, this->vpn_service, method_id, NULL);
	if (!jcerts || androidjni_exception_occurred(env))
	{
		goto failed;
	}
	list = convert_array_of_byte_arrays(env, jcerts);
	androidjni_detach_thread();
	return list;

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return NULL;
}

METHOD(charonservice_t, get_user_certificate, linked_list_t*,
	private_charonservice_t *this)
{
	JNIEnv *env;
	jmethodID method_id;
	jobjectArray jencodings;
	linked_list_t *list;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env,
						android_charonvpnservice_class,
						"getUserCertificate", "()[[B");
	if (!method_id)
	{
		goto failed;
	}
	jencodings = (*env)->CallObjectMethod(env, this->vpn_service, method_id);
	if (!jencodings || androidjni_exception_occurred(env))
	{
		goto failed;
	}
	list = convert_array_of_byte_arrays(env, jencodings);
	androidjni_detach_thread();
	return list;

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return NULL;
}

METHOD(charonservice_t, get_user_key, private_key_t*,
	private_charonservice_t *this, public_key_t *pubkey)
{
	JNIEnv *env;
	jmethodID method_id;
	private_key_t *key;
	jobject jkey;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env,
						android_charonvpnservice_class,
						"getUserKey", "()Ljava/security/PrivateKey;");
	if (!method_id)
	{
		goto failed;
	}
	jkey = (*env)->CallObjectMethod(env, this->vpn_service, method_id);
	if (!jkey || androidjni_exception_occurred(env))
	{
		goto failed;
	}
	key = android_private_key_create(jkey, pubkey);
	androidjni_detach_thread();
	return key;

failed:
	DESTROY_IF(pubkey);
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return NULL;
}

METHOD(charonservice_t, get_vpnservice_builder, vpnservice_builder_t*,
	private_charonservice_t *this)
{
	return this->builder;
}

METHOD(charonservice_t, get_network_manager, network_manager_t*,
	private_charonservice_t *this)
{
	return this->network_manager;
}

/**
 * Initiate a new connection
 *
 * @param gateway			gateway address (gets owned)
 * @param username			username (gets owned)
 * @param password			password (gets owned)
 */
static void initiate(char *type, char *gateway, char *username, char *password)
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;

	this->creds->clear(this->creds);
	DESTROY_IF(this->service);
	this->service = android_service_create(this->creds, type, gateway,
										   username, password);
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
static void charonservice_init(JNIEnv *env, jobject service, jobject builder,
							   char *logfile)
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
			.get_user_certificate = _get_user_certificate,
			.get_user_key = _get_user_key,
			.get_vpnservice_builder = _get_vpnservice_builder,
			.get_network_manager = _get_network_manager,
		},
		.attr = android_attr_create(),
		.creds = android_creds_create(),
		.builder = vpnservice_builder_create(builder),
		.network_manager = network_manager_create(service),
		.sockets = linked_list_create(),
		.vpn_service = (*env)->NewGlobalRef(env, service),
	);
	charonservice = &this->public;

	lib->plugins->add_static_features(lib->plugins, "androidbridge", features,
									  countof(features), TRUE);

	lib->settings->set_int(lib->settings,
					"charon.plugins.android_log.loglevel", ANDROID_DEBUG_LEVEL);
	/* setup file logger */
	lib->settings->set_str(lib->settings,
					"charon.filelog.%s.time_format", "%b %e %T", logfile);
	lib->settings->set_bool(lib->settings,
					"charon.filelog.%s.append", FALSE, logfile);
	lib->settings->set_bool(lib->settings,
					"charon.filelog.%s.flush_line", TRUE, logfile);
	lib->settings->set_int(lib->settings,
					"charon.filelog.%s.default", ANDROID_DEBUG_LEVEL, logfile);

	lib->settings->set_int(lib->settings,
					"charon.retransmit_tries", ANDROID_RETRASNMIT_TRIES);
	lib->settings->set_double(lib->settings,
					"charon.retransmit_timeout", ANDROID_RETRANSMIT_TIMEOUT);
	lib->settings->set_double(lib->settings,
					"charon.retransmit_base", ANDROID_RETRANSMIT_BASE);
	lib->settings->set_bool(lib->settings,
					"charon.close_ike_on_child_failure", TRUE);
	/* setting the source address breaks the VpnService.protect() function which
	 * uses SO_BINDTODEVICE internally.  the addresses provided to the kernel as
	 * auxiliary data have precedence over this option causing a routing loop if
	 * the gateway is contained in the VPN routes.  alternatively, providing an
	 * explicit device (in addition or instead of the source address) in the
	 * auxiliary data would also work, but we currently don't have that
	 * information */
	lib->settings->set_bool(lib->settings,
					"charon.plugins.socket-default.set_source", FALSE);
}

/**
 * Deinitialize the charonservice object
 */
static void charonservice_deinit(JNIEnv *env)
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;

	this->network_manager->destroy(this->network_manager);
	this->sockets->destroy(this->sockets);
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
	jobject builder, jstring jlogfile)
{
	struct sigaction action;
	struct utsname utsname;
	char *logfile;

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

	if (!libcharon_init("charon"))
	{
		libcharon_deinit();
		libipsec_deinit();
		libhydra_deinit();
		library_deinit();
		return;
	}

	logfile = androidjni_convert_jstring(env, jlogfile);
	charonservice_init(env, this, builder, logfile);
	free(logfile);

	charon->load_loggers(charon, NULL, FALSE);

	if (uname(&utsname) != 0)
	{
		memset(&utsname, 0, sizeof(utsname));
	}
	DBG1(DBG_DMN, "Starting IKE charon daemon (strongSwan "VERSION", %s %s, %s)",
		  utsname.sysname, utsname.release, utsname.machine);

	if (!charon->initialize(charon, PLUGINS))
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
	/* deinitialize charon before we destroy our own objects */
	libcharon_deinit();
	charonservice_deinit(env);
	libipsec_deinit();
	libhydra_deinit();
	library_deinit();
}

/**
 * Initiate SA
 */
JNI_METHOD(CharonVpnService, initiate, void,
	jstring jtype, jstring jgateway, jstring jusername, jstring jpassword)
{
	char *type, *gateway, *username, *password;

	type = androidjni_convert_jstring(env, jtype);
	gateway = androidjni_convert_jstring(env, jgateway);
	username = androidjni_convert_jstring(env, jusername);
	password = androidjni_convert_jstring(env, jpassword);

	initiate(type, gateway, username, password);
}
