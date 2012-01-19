/*
 * Copyright (C) 2006-2010 Tobias Brunner
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

#ifdef CAPABILITIES
# ifdef HAVE_SYS_CAPABILITY_H
#  include <sys/capability.h>
# elif defined(CAPABILITIES_NATIVE)
#  include <linux/capability.h>
# endif /* CAPABILITIES_NATIVE */
#endif /* CAPABILITIES */

#include "daemon.h"

#include <library.h>
#include <plugins/plugin.h>
#include <config/proposal.h>
#include <kernel/kernel_handler.h>
#include <processing/jobs/start_action_job.h>

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

	/**
	 * capabilities to keep
	 */
#ifdef CAPABILITIES_LIBCAP
	cap_t caps;
#endif /* CAPABILITIES_LIBCAP */
#ifdef CAPABILITIES_NATIVE
	struct __user_cap_data_struct caps[2];
#endif /* CAPABILITIES_NATIVE */

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
	DESTROY_IF(this->public.receiver);
	DESTROY_IF(this->public.sender);
#ifdef ME
	DESTROY_IF(this->public.connect_manager);
	DESTROY_IF(this->public.mediation_manager);
#endif /* ME */
	/* make sure the cache is clear before unloading plugins */
	lib->credmgr->flush_cache(lib->credmgr, CERT_ANY);
	/* unload plugins to release threads */
	lib->plugins->unload(lib->plugins);
#ifdef CAPABILITIES_LIBCAP
	cap_free(this->caps);
#endif /* CAPABILITIES_LIBCAP */
	DESTROY_IF(this->kernel_handler);
	DESTROY_IF(this->public.traps);
	DESTROY_IF(this->public.shunts);
	DESTROY_IF(this->public.ike_sa_manager);
	DESTROY_IF(this->public.controller);
	DESTROY_IF(this->public.eap);
	DESTROY_IF(this->public.backends);
	DESTROY_IF(this->public.socket);

	/* rehook library logging, shutdown logging */
	dbg = dbg_old;
	DESTROY_IF(this->public.bus);
	this->public.file_loggers->destroy_offset(this->public.file_loggers,
											offsetof(file_logger_t, destroy));
	this->public.sys_loggers->destroy_offset(this->public.sys_loggers,
											offsetof(sys_logger_t, destroy));
	free(this);
}

METHOD(daemon_t, keep_cap, void,
	   private_daemon_t *this, u_int cap)
{
#ifdef CAPABILITIES_LIBCAP
	cap_set_flag(this->caps, CAP_EFFECTIVE, 1, &cap, CAP_SET);
	cap_set_flag(this->caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap_set_flag(this->caps, CAP_PERMITTED, 1, &cap, CAP_SET);
#endif /* CAPABILITIES_LIBCAP */
#ifdef CAPABILITIES_NATIVE
	int i = 0;

	if (cap >= 32)
	{
		i++;
		cap -= 32;
	}
	this->caps[i].effective |= 1 << cap;
	this->caps[i].permitted |= 1 << cap;
	this->caps[i].inheritable |= 1 << cap;
#endif /* CAPABILITIES_NATIVE */
}

METHOD(daemon_t, drop_capabilities, bool,
	   private_daemon_t *this)
{
#ifdef CAPABILITIES_LIBCAP
	if (cap_set_proc(this->caps) != 0)
	{
		return FALSE;
	}
#endif /* CAPABILITIES_LIBCAP */
#ifdef CAPABILITIES_NATIVE
	struct __user_cap_header_struct header = {
#if defined(_LINUX_CAPABILITY_VERSION_3)
		.version = _LINUX_CAPABILITY_VERSION_3,
#elif defined(_LINUX_CAPABILITY_VERSION_2)
		.version = _LINUX_CAPABILITY_VERSION_2,
#elif defined(_LINUX_CAPABILITY_VERSION_1)
		.version = _LINUX_CAPABILITY_VERSION_1,
#else
		.version = _LINUX_CAPABILITY_VERSION,
#endif
	};
	if (capset(&header, this->caps) != 0)
	{
		return FALSE;
	}
#endif /* CAPABILITIES_NATIVE */
	return TRUE;
}

METHOD(daemon_t, start, void,
	   private_daemon_t *this)
{
	/* start the engine, go multithreaded */
	lib->processor->set_threads(lib->processor,
						lib->settings->get_int(lib->settings, "charon.threads",
											   DEFAULT_THREADS));
}

METHOD(daemon_t, initialize, bool,
	private_daemon_t *this)
{
	DBG1(DBG_DMN, "Starting IKEv2 charon daemon (strongSwan "VERSION")");

	if (lib->integrity)
	{
		DBG1(DBG_DMN, "integrity tests enabled:");
		DBG1(DBG_DMN, "lib    'libstrongswan': passed file and segment integrity tests");
		DBG1(DBG_DMN, "lib    'libhydra': passed file and segment integrity tests");
		DBG1(DBG_DMN, "lib    'libcharon': passed file and segment integrity tests");
		DBG1(DBG_DMN, "daemon 'charon': passed file integrity test");
	}

	/* load plugins, further infrastructure may need it */
	if (!lib->plugins->load(lib->plugins, NULL,
			lib->settings->get_str(lib->settings, "charon.load", PLUGINS)))
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
	this->public.sender = sender_create();
	this->public.receiver = receiver_create();
	if (this->public.receiver == NULL)
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
private_daemon_t *daemon_create()
{
	private_daemon_t *this;

	INIT(this,
		.public = {
			.keep_cap = _keep_cap,
			.drop_capabilities = _drop_capabilities,
			.initialize = _initialize,
			.start = _start,
			.bus = bus_create(),
			.file_loggers = linked_list_create(),
			.sys_loggers = linked_list_create(),
		},
	);
	charon = &this->public;
	this->public.controller = controller_create();
	this->public.eap = eap_manager_create();
	this->public.backends = backend_manager_create();
	this->public.socket = socket_manager_create();
	this->public.traps = trap_manager_create();
	this->public.shunts = shunt_manager_create();
	this->kernel_handler = kernel_handler_create();

#ifdef CAPABILITIES
#ifdef CAPABILITIES_LIBCAP
	this->caps = cap_init();
#endif /* CAPABILITIES_LIBCAP */
	keep_cap(this, CAP_NET_ADMIN);
	if (lib->leak_detective)
	{
		keep_cap(this, CAP_SYS_NICE);
	}
#endif /* CAPABILITIES */

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
bool libcharon_init()
{
	daemon_create();

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
