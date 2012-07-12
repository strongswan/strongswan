/*
 * Copyright (C) 2006-2012 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005 Jan Hutter
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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include "daemon.h"

#include <library.h>
#include <plugins/plugin_feature.h>
#include <config/proposal.h>
#include <kernel/kernel_handler.h>
#include <processing/jobs/start_action_job.h>

#ifndef CAP_NET_ADMIN
#define CAP_NET_ADMIN 12
#endif

typedef struct private_daemon_t private_daemon_t;

/**
 * Private additions to daemon_t, contains threads and internal functions.
 */
struct private_daemon_t {
	/**
	 * Public members of daemon_t.
	 */
	daemon_t public;

	/**
	 * Handler for kernel events
	 */
	kernel_handler_t *kernel_handler;
};

/**
 * One and only instance of the daemon.
 */
daemon_t *charon;

/**
 * hook in library for debugging messages
 */
extern void (*dbg) (debug_t group, level_t level, char *fmt, ...);

/**
 * we store the previous debug function so we can reset it
 */
static void (*dbg_old) (debug_t group, level_t level, char *fmt, ...);

/**
 * Logging hook for library logs, spreads debug message over bus
 */
static void dbg_bus(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	charon->bus->vlog(charon->bus, group, level, fmt, args);
	va_end(args);
}

/**
 * Clean up all daemon resources
 */
static void destroy(private_daemon_t *this)
{
	/* terminate all idle threads */
	lib->processor->set_threads(lib->processor, 0);

	/* close all IKE_SAs */
	if (this->public.ike_sa_manager)
	{
		this->public.ike_sa_manager->flush(this->public.ike_sa_manager);
	}
	if (this->public.traps)
	{
		this->public.traps->flush(this->public.traps);
	}
	if (this->public.sender)
	{
		this->public.sender->flush(this->public.sender);
	}

	/* cancel all threads and wait for their termination */
	lib->processor->cancel(lib->processor);

#ifdef ME
	DESTROY_IF(this->public.connect_manager);
	DESTROY_IF(this->public.mediation_manager);
#endif /* ME */
	/* make sure the cache is clear before unloading plugins */
	lib->credmgr->flush_cache(lib->credmgr, CERT_ANY);
	lib->plugins->unload(lib->plugins);
	DESTROY_IF(this->kernel_handler);
	DESTROY_IF(this->public.traps);
	DESTROY_IF(this->public.shunts);
	DESTROY_IF(this->public.ike_sa_manager);
	DESTROY_IF(this->public.controller);
	DESTROY_IF(this->public.eap);
	DESTROY_IF(this->public.xauth);
	DESTROY_IF(this->public.backends);
	DESTROY_IF(this->public.socket);
	DESTROY_IF(this->public.caps);

	/* rehook library logging, shutdown logging */
	dbg = dbg_old;
	DESTROY_IF(this->public.bus);
	this->public.file_loggers->destroy_offset(this->public.file_loggers,
											offsetof(file_logger_t, destroy));
	this->public.sys_loggers->destroy_offset(this->public.sys_loggers,
											offsetof(sys_logger_t, destroy));
	free((void*)this->public.name);
	free(this);
}

METHOD(daemon_t, start, void,
	   private_daemon_t *this)
{
	/* start the engine, go multithreaded */
	lib->processor->set_threads(lib->processor,
						lib->settings->get_int(lib->settings, "%s.threads",
											   DEFAULT_THREADS, charon->name));
}


/**
 * Initialize/deinitialize sender and receiver
 */
static bool sender_receiver_cb(void *plugin, plugin_feature_t *feature,
							   bool reg, private_daemon_t *this)
{
	if (reg)
	{
		this->public.receiver = receiver_create();
		if (!this->public.receiver)
		{
			return FALSE;
		}
		this->public.sender = sender_create();
	}
	else
	{
		DESTROY_IF(this->public.receiver);
		DESTROY_IF(this->public.sender);
	}
	return TRUE;
}

METHOD(daemon_t, initialize, bool,
	private_daemon_t *this, char *plugins)
{
	plugin_feature_t features[] = {
		PLUGIN_PROVIDE(CUSTOM, "libcharon"),
			PLUGIN_DEPENDS(NONCE_GEN),
			PLUGIN_DEPENDS(CUSTOM, "libcharon-receiver"),
			PLUGIN_DEPENDS(CUSTOM, "kernel-ipsec"),
			PLUGIN_DEPENDS(CUSTOM, "kernel-net"),
		PLUGIN_CALLBACK((plugin_feature_callback_t)sender_receiver_cb, this),
			PLUGIN_PROVIDE(CUSTOM, "libcharon-receiver"),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
				PLUGIN_DEPENDS(CUSTOM, "socket"),
	};
	lib->plugins->add_static_features(lib->plugins, charon->name, features,
									  countof(features), TRUE);

	/* load plugins, further infrastructure may need it */
	if (!lib->plugins->load(lib->plugins, NULL, plugins))
	{
		return FALSE;
	}
	DBG1(DBG_DMN, "loaded plugins: %s",
		 lib->plugins->loaded_plugins(lib->plugins));

	this->public.ike_sa_manager = ike_sa_manager_create();
	if (this->public.ike_sa_manager == NULL)
	{
		return FALSE;
	}

	/* Queue start_action job */
	lib->processor->queue_job(lib->processor, (job_t*)start_action_job_create());

#ifdef ME
	this->public.connect_manager = connect_manager_create();
	if (this->public.connect_manager == NULL)
	{
		return FALSE;
	}
	this->public.mediation_manager = mediation_manager_create();
#endif /* ME */

	return TRUE;
}

/**
 * Create the daemon.
 */
private_daemon_t *daemon_create(const char *name)
{
	private_daemon_t *this;

	INIT(this,
		.public = {
			.initialize = _initialize,
			.start = _start,
			.bus = bus_create(),
			.file_loggers = linked_list_create(),
			.sys_loggers = linked_list_create(),
			.name = strdup(name ?: "libcharon"),
		},
	);
	charon = &this->public;
	this->public.caps = capabilities_create();
	this->public.controller = controller_create();
	this->public.eap = eap_manager_create();
	this->public.xauth = xauth_manager_create();
	this->public.backends = backend_manager_create();
	this->public.socket = socket_manager_create();
	this->public.traps = trap_manager_create();
	this->public.shunts = shunt_manager_create();
	this->kernel_handler = kernel_handler_create();

	this->public.caps->keep(this->public.caps, CAP_NET_ADMIN);

	return this;
}

/**
 * Described in header.
 */
void libcharon_deinit()
{
	destroy((private_daemon_t*)charon);
	charon = NULL;
}

/**
 * Described in header.
 */
bool libcharon_init(const char *name)
{
	daemon_create(name);

	/* for uncritical pseudo random numbers */
	srandom(time(NULL) + getpid());

	/* set up hook to log dbg message in library via charons message bus */
	dbg_old = dbg;
	dbg = dbg_bus;

	lib->printf_hook->add_handler(lib->printf_hook, 'P',
								  proposal_printf_hook,
								  PRINTF_HOOK_ARGTYPE_POINTER,
								  PRINTF_HOOK_ARGTYPE_END);

	if (lib->integrity &&
		!lib->integrity->check(lib->integrity, "libcharon", libcharon_init))
	{
		dbg(DBG_DMN, 1, "integrity check of libcharon failed");
		return FALSE;
	}

	return TRUE;
}
