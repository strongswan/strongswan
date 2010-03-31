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
#include <errno.h>
#ifdef CAPABILITIES
#include <sys/capability.h>
#endif /* CAPABILITIES */

#include "daemon.h"

#include <library.h>
#include <selectors/traffic_selector.h>
#include <config/proposal.h>

#ifndef LOG_AUTHPRIV /* not defined on OpenSolaris */
#define LOG_AUTHPRIV LOG_AUTH
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

#ifdef CAPABILITIES
	/**
	 * capabilities to keep
	 */
	cap_t caps;
#endif /* CAPABILITIES */
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
	if (this->public.processor)
	{
		this->public.processor->set_threads(this->public.processor, 0);
	}
	/* close all IKE_SAs */
	if (this->public.ike_sa_manager)
	{
		this->public.ike_sa_manager->flush(this->public.ike_sa_manager);
	}
	DESTROY_IF(this->public.receiver);
	/* unload plugins to release threads */
	lib->plugins->unload(lib->plugins);
#ifdef CAPABILITIES
	cap_free(this->caps);
#endif /* CAPABILITIES */
	DESTROY_IF(this->public.traps);
	DESTROY_IF(this->public.ike_sa_manager);
	DESTROY_IF(this->public.kernel_interface);
	DESTROY_IF(this->public.scheduler);
	DESTROY_IF(this->public.controller);
	DESTROY_IF(this->public.eap);
	DESTROY_IF(this->public.sim);
#ifdef ME
	DESTROY_IF(this->public.connect_manager);
	DESTROY_IF(this->public.mediation_manager);
#endif /* ME */
	DESTROY_IF(this->public.backends);
	DESTROY_IF(this->public.credentials);
	DESTROY_IF(this->public.sender);
	DESTROY_IF(this->public.socket);
	/* wait until all threads are gone */
	DESTROY_IF(this->public.processor);

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
#ifdef CAPABILITIES
	cap_set_flag(this->caps, CAP_EFFECTIVE, 1, &cap, CAP_SET);
	cap_set_flag(this->caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap_set_flag(this->caps, CAP_PERMITTED, 1, &cap, CAP_SET);
#endif /* CAPABILITIES */
}

METHOD(daemon_t, drop_capabilities, bool,
	   private_daemon_t *this)
{
#ifdef CAPABILITIES
	if (cap_set_proc(this->caps) != 0)
	{
		return FALSE;
	}
#endif /* CAPABILITIES */
	return TRUE;
}

METHOD(daemon_t, start, void,
	   private_daemon_t *this)
{
	/* start the engine, go multithreaded */
	charon->processor->set_threads(charon->processor,
						lib->settings->get_int(lib->settings, "charon.threads",
											   DEFAULT_THREADS));
}

/**
 * Log loaded plugins
 */
static void print_plugins()
{
	char buf[512], *plugin;
	int len = 0;
	enumerator_t *enumerator;

	buf[0] = '\0';
	enumerator = lib->plugins->create_plugin_enumerator(lib->plugins);
	while (len < sizeof(buf) && enumerator->enumerate(enumerator, &plugin))
	{
		len += snprintf(&buf[len], sizeof(buf)-len, "%s ", plugin);
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_DMN, "loaded plugins: %s", buf);
}

/**
 * Initialize logging
 */
static void initialize_loggers(private_daemon_t *this, bool use_stderr,
							   level_t levels[])
{
	sys_logger_t *sys_logger;
	file_logger_t *file_logger;
	enumerator_t *enumerator;
	char *facility, *filename;
	int loggers_defined = 0;
	debug_t group;
	level_t  def;
	bool append;
	FILE *file;

	/* setup sysloggers */
	enumerator = lib->settings->create_section_enumerator(lib->settings,
														  "charon.syslog");
	while (enumerator->enumerate(enumerator, &facility))
	{
		loggers_defined++;
		if (streq(facility, "daemon"))
		{
			sys_logger = sys_logger_create(LOG_DAEMON);
		}
		else if (streq(facility, "auth"))
		{
			sys_logger = sys_logger_create(LOG_AUTHPRIV);
		}
		else
		{
			continue;
		}
		def = lib->settings->get_int(lib->settings,
									 "charon.syslog.%s.default", 1, facility);
		for (group = 0; group < DBG_MAX; group++)
		{
			sys_logger->set_level(sys_logger, group,
				lib->settings->get_int(lib->settings,
									   "charon.syslog.%s.%N", def,
									   facility, debug_lower_names, group));
		}
		this->public.sys_loggers->insert_last(this->public.sys_loggers,
											  sys_logger);
		this->public.bus->add_listener(this->public.bus, &sys_logger->listener);
	}
	enumerator->destroy(enumerator);

	/* and file loggers */
	enumerator = lib->settings->create_section_enumerator(lib->settings,
														  "charon.filelog");
	while (enumerator->enumerate(enumerator, &filename))
	{
		loggers_defined++;
		if (streq(filename, "stderr"))
		{
			file = stderr;
		}
		else if (streq(filename, "stdout"))
		{
			file = stdout;
		}
		else
		{
			append = lib->settings->get_bool(lib->settings,
									"charon.filelog.%s.append", TRUE, filename);
			file = fopen(filename, append ? "a" : "w");
			if (file == NULL)
			{
				DBG1(DBG_DMN, "opening file %s for logging failed: %s",
					 filename, strerror(errno));
				continue;
			}
		}
		file_logger = file_logger_create(file);
		def = lib->settings->get_int(lib->settings,
									 "charon.filelog.%s.default", 1, filename);
		for (group = 0; group < DBG_MAX; group++)
		{
			file_logger->set_level(file_logger, group,
				lib->settings->get_int(lib->settings,
									   "charon.filelog.%s.%N", def,
									   filename, debug_lower_names, group));
		}
		this->public.file_loggers->insert_last(this->public.file_loggers,
											   file_logger);
		this->public.bus->add_listener(this->public.bus, &file_logger->listener);

	}
	enumerator->destroy(enumerator);

	/* set up legacy style default loggers provided via command-line */
	if (!loggers_defined)
	{
		/* set up default stdout file_logger */
		file_logger = file_logger_create(stdout);
		this->public.bus->add_listener(this->public.bus, &file_logger->listener);
		this->public.file_loggers->insert_last(this->public.file_loggers,
											   file_logger);
		/* set up default daemon sys_logger */
		sys_logger = sys_logger_create(LOG_DAEMON);
		this->public.bus->add_listener(this->public.bus, &sys_logger->listener);
		this->public.sys_loggers->insert_last(this->public.sys_loggers,
											  sys_logger);
		for (group = 0; group < DBG_MAX; group++)
		{
			sys_logger->set_level(sys_logger, group, levels[group]);
			if (use_stderr)
			{
				file_logger->set_level(file_logger, group, levels[group]);
			}
		}

		/* set up default auth sys_logger */
		sys_logger = sys_logger_create(LOG_AUTHPRIV);
		this->public.bus->add_listener(this->public.bus, &sys_logger->listener);
		this->public.sys_loggers->insert_last(this->public.sys_loggers,
											  sys_logger);
		sys_logger->set_level(sys_logger, DBG_ANY, LEVEL_AUDIT);
	}
}

METHOD(daemon_t, initialize, bool,
	   private_daemon_t *this, bool syslog, level_t levels[])
{
	/* for uncritical pseudo random numbers */
	srandom(time(NULL) + getpid());

	/* setup bus and it's listeners first to enable log output */
	this->public.bus = bus_create();
	/* set up hook to log dbg message in library via charons message bus */
	dbg_old = dbg;
	dbg = dbg_bus;

	initialize_loggers(this, !syslog, levels);

	DBG1(DBG_DMN, "Starting IKEv2 charon daemon (strongSwan "VERSION")");

	if (lib->integrity)
	{
		DBG1(DBG_DMN, "integrity tests enabled:");
		DBG1(DBG_DMN, "lib    'libstrongswan': passed file and segment integrity tests");
		DBG1(DBG_DMN, "lib    'libhydra': passed file and segment integrity tests");
		DBG1(DBG_DMN, "lib    'libcharon': passed file and segment integrity tests");
		DBG1(DBG_DMN, "daemon 'charon': passed file integrity test");
	}

	/* load secrets, ca certificates and crls */
	this->public.processor = processor_create();
	this->public.scheduler = scheduler_create();
	this->public.credentials = credential_manager_create();
	this->public.controller = controller_create();
	this->public.eap = eap_manager_create();
	this->public.sim = sim_manager_create();
	this->public.backends = backend_manager_create();
	this->public.kernel_interface = kernel_interface_create();
	this->public.socket = socket_manager_create();
	this->public.traps = trap_manager_create();

	/* load plugins, further infrastructure may need it */
	if (!lib->plugins->load(lib->plugins, NULL,
			lib->settings->get_str(lib->settings, "charon.load", PLUGINS)))
	{
		return FALSE;
	}

	print_plugins();

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
			.file_loggers = linked_list_create(),
			.sys_loggers = linked_list_create(),
		},
	);

#ifdef CAPABILITIES
	this->caps = cap_init();
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
	private_daemon_t *this;

	this = daemon_create();
	charon = &this->public;

	lib->printf_hook->add_handler(lib->printf_hook, 'R',
								  traffic_selector_printf_hook,
								  PRINTF_HOOK_ARGTYPE_POINTER,
								  PRINTF_HOOK_ARGTYPE_END);
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
