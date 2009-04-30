/* 
 * Copyright (C) 2006-2009 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005-2008 Martin Willi
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
#ifdef HAVE_PRCTL
#include <sys/prctl.h>
#endif
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#ifdef CAPABILITIES
#include <sys/capability.h>
#endif /* CAPABILITIES */

#include "daemon.h"

#include <library.h>
#include <utils/backtrace.h>
#include <config/traffic_selector.h>
#include <config/proposal.h>

#ifdef INTEGRITY_TEST
#include <fips/fips.h>
#include <fips/fips_signature.h>
#endif /* INTEGRITY_TEST */

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
	 * Signal set used for signal handling.
	 */
	sigset_t signal_set;

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
extern void (*dbg) (int level, char *fmt, ...);

/**
 * Logging hook for library logs, spreads debug message over bus
 */
static void dbg_bus(int level, char *fmt, ...)
{
	va_list args;
	
	va_start(args, fmt);
	charon->bus->vlog(charon->bus, DBG_LIB, level, fmt, args);
	va_end(args);
}

/**
 * Logging hook for library logs, using stderr output
 */
static void dbg_stderr(int level, char *fmt, ...)
{
	va_list args;
	
	if (level <= 1)
	{
		va_start(args, fmt);
		fprintf(stderr, "00[LIB] ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
}

/**
 * Run the daemon and handle unix signals
 */
static void run(private_daemon_t *this)
{
	sigset_t set;
	
	/* handle SIGINT, SIGHUP ans SIGTERM in this handler */
	sigemptyset(&set);
	sigaddset(&set, SIGINT); 
	sigaddset(&set, SIGHUP); 
	sigaddset(&set, SIGTERM);
	
	while (TRUE)
	{
		int sig;
		int error;
		
		error = sigwait(&set, &sig);
		if (error)
		{
			DBG1(DBG_DMN, "error %d while waiting for a signal", error);
			return;
		}
		switch (sig)
		{
			case SIGHUP:
			{
				DBG1(DBG_DMN, "signal of type SIGHUP received. Ignored");
				break;
			}
			case SIGINT:
			{
				DBG1(DBG_DMN, "signal of type SIGINT received. Shutting down");
				return;
			}
			case SIGTERM:
			{
				DBG1(DBG_DMN, "signal of type SIGTERM received. Shutting down");
				return;
			}
			default:
			{
				DBG1(DBG_DMN, "unknown signal %d received. Ignored", sig);
				break;
			}
		}
	}
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
	/* unload plugins to release threads */
	lib->plugins->unload(lib->plugins);
#ifdef CAPABILITIES
	cap_free(this->caps);
#endif /* CAPABILITIES */
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
	DESTROY_IF(this->public.attributes);
	DESTROY_IF(this->public.credentials);
	DESTROY_IF(this->public.sender);
	DESTROY_IF(this->public.receiver);
	DESTROY_IF(this->public.socket);
	/* wait until all threads are gone */
	DESTROY_IF(this->public.processor);
	
	/* rehook library logging, shutdown logging */
	dbg = dbg_stderr;
	DESTROY_IF(this->public.bus);
	this->public.file_loggers->destroy_offset(this->public.file_loggers,
											offsetof(file_logger_t, destroy));
	this->public.sys_loggers->destroy_offset(this->public.sys_loggers,
											offsetof(sys_logger_t, destroy));
	free(this);
}

/**
 * Enforce daemon shutdown, with a given reason to do so.
 */
static void kill_daemon(private_daemon_t *this, char *reason)
{
	/* we send SIGTERM, so the daemon can cleanly shut down */
	if (this->public.bus)
	{
		DBG1(DBG_DMN, "killing daemon: %s", reason);
	}
	else
	{
		fprintf(stderr, "killing daemon: %s\n", reason);
	}
	if (this->public.main_thread_id == pthread_self())
	{
		/* initialization failed, terminate daemon */
		unlink(PID_FILE);
		exit(-1);
	}
	else
	{
		DBG1(DBG_DMN, "sending SIGTERM to ourself");
		pthread_kill(this->public.main_thread_id, SIGTERM);
		/* thread must die, since he produced a ciritcal failure and can't continue */
		pthread_exit(NULL);
	}
}

/**
 * drop daemon capabilities
 */
static void drop_capabilities(private_daemon_t *this)
{
#ifdef HAVE_PRCTL
	prctl(PR_SET_KEEPCAPS, 1);
#endif

	if (setgid(charon->gid) != 0)
	{
		kill_daemon(this, "change to unprivileged group failed");	
	}
	if (setuid(charon->uid) != 0)
	{
		kill_daemon(this, "change to unprivileged user failed");	
	}
	
#ifdef CAPABILITIES
	if (cap_set_proc(this->caps) != 0)
	{
		kill_daemon(this, "unable to drop daemon capabilities");
	}
#endif /* CAPABILITIES */
}

/**
 * Implementation of daemon_t.keep_cap
 */
static void keep_cap(private_daemon_t *this, u_int cap)
{
#ifdef CAPABILITIES
	cap_set_flag(this->caps, CAP_EFFECTIVE, 1, &cap, CAP_SET);
	cap_set_flag(this->caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap_set_flag(this->caps, CAP_PERMITTED, 1, &cap, CAP_SET);
#endif /* CAPABILITIES */
}

/**
 * lookup UID and GID 
 */
static void lookup_uid_gid(private_daemon_t *this)
{
#ifdef IPSEC_USER
	{
		char buf[1024];
		struct passwd passwd, *pwp;
	
		if (getpwnam_r(IPSEC_USER, &passwd, buf, sizeof(buf), &pwp) != 0 ||
			pwp == NULL)
		{
			kill_daemon(this, "resolving user '"IPSEC_USER"' failed");
		}
		charon->uid = pwp->pw_uid;
	}
#endif
#ifdef IPSEC_GROUP
	{
		char buf[1024];
		struct group group, *grp;
	
		if (getgrnam_r(IPSEC_GROUP, &group, buf, sizeof(buf), &grp) != 0 ||
			grp == NULL)
		{
			kill_daemon(this, "resolving group '"IPSEC_GROUP"' failed");
		}
		charon->gid = grp->gr_gid;
	}
#endif
}

/**
 * Log loaded plugins
 */
static void print_plugins()
{
	char buf[512], *plugin;
	int len = 0;
	enumerator_t *enumerator;
	
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

/**
 * Initialize the daemon
 */
static bool initialize(private_daemon_t *this, bool syslog, level_t levels[])
{
	/* for uncritical pseudo random numbers */
	srandom(time(NULL) + getpid());
	
	/* setup bus and it's listeners first to enable log output */
	this->public.bus = bus_create();
	/* set up hook to log dbg message in library via charons message bus */
	dbg = dbg_bus;
	
	initialize_loggers(this, !syslog, levels);
	
	DBG1(DBG_DMN, "starting charon (strongSwan Version %s)", VERSION);

	/* load secrets, ca certificates and crls */
	this->public.processor = processor_create();
	this->public.scheduler = scheduler_create();
	this->public.credentials = credential_manager_create();
	this->public.controller = controller_create();
	this->public.eap = eap_manager_create();
	this->public.sim = sim_manager_create();
	this->public.backends = backend_manager_create();
	this->public.attributes = attribute_manager_create();
	this->public.kernel_interface = kernel_interface_create();
	this->public.socket = socket_create();
	
	/* load plugins, further infrastructure may need it */
	lib->plugins->load(lib->plugins, IPSEC_PLUGINDIR, 
		lib->settings->get_str(lib->settings, "charon.load", PLUGINS));
	
	print_plugins();
	
	/* create the kernel interfaces */
	this->public.kernel_interface->create_interfaces(this->public.kernel_interface);
	
#ifdef INTEGRITY_TEST
	DBG1(DBG_DMN, "integrity test of libstrongswan code");
	if (fips_verify_hmac_signature(hmac_key, hmac_signature))
	{
		DBG1(DBG_DMN, "  integrity test passed");
	}
	else
	{
		DBG1(DBG_DMN, "  integrity test failed");
		return FALSE;
	}
#endif /* INTEGRITY_TEST */

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
 * Handle SIGSEGV/SIGILL signals raised by threads
 */
static void segv_handler(int signal)
{
	backtrace_t *backtrace;
	
	DBG1(DBG_DMN, "thread %u received %d", pthread_self(), signal);
	backtrace = backtrace_create(2);
	backtrace->log(backtrace, stderr);
	backtrace->destroy(backtrace);
	
	DBG1(DBG_DMN, "killing ourself, received critical signal");
	raise(SIGKILL);
}

/**
 * Create the daemon.
 */
private_daemon_t *daemon_create(void)
{	
	struct sigaction action;
	private_daemon_t *this = malloc_thing(private_daemon_t);
		
	/* assign methods */
	this->public.kill = (void (*) (daemon_t*,char*))kill_daemon;
	this->public.keep_cap = (void(*)(daemon_t*, u_int cap))keep_cap;
	
	/* NULL members for clean destruction */
	this->public.socket = NULL;
	this->public.ike_sa_manager = NULL;
	this->public.credentials = NULL;
	this->public.backends = NULL;
	this->public.attributes = NULL;
	this->public.sender= NULL;
	this->public.receiver = NULL;
	this->public.scheduler = NULL;
	this->public.kernel_interface = NULL;
	this->public.processor = NULL;
	this->public.controller = NULL;
	this->public.eap = NULL;
	this->public.sim = NULL;
	this->public.bus = NULL;
	this->public.file_loggers = linked_list_create();
	this->public.sys_loggers = linked_list_create();
#ifdef ME
	this->public.connect_manager = NULL;
	this->public.mediation_manager = NULL;
#endif /* ME */
	this->public.uid = 0;
	this->public.gid = 0;
	
	this->public.main_thread_id = pthread_self();
#ifdef CAPABILITIES
	this->caps = cap_init();
	keep_cap(this, CAP_NET_ADMIN);
	if (lib->leak_detective)
	{
		keep_cap(this, CAP_SYS_NICE);
	}
#endif /* CAPABILITIES */
	
	/* add handler for SEGV and ILL,
	 * add handler for USR1 (cancellation).
	 * INT, TERM and HUP are handled by sigwait() in run() */
	action.sa_handler = segv_handler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGINT);
	sigaddset(&action.sa_mask, SIGTERM);
	sigaddset(&action.sa_mask, SIGHUP);
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
	
	pthread_sigmask(SIG_SETMASK, &action.sa_mask, 0);
	
	return this;
}

/**
 * print command line usage and exit
 */
static void usage(const char *msg)
{
	if (msg != NULL && *msg != '\0')
	{
		fprintf(stderr, "%s\n", msg);
	}
	fprintf(stderr, "Usage: charon\n"
					"         [--help]\n"
					"         [--version]\n"
					"         [--use-syslog]\n"
					"         [--debug-<type> <level>]\n"
					"           <type>:  log context type (dmn|mgr|ike|chd|job|cfg|knl|net|enc|lib)\n"
					"           <level>: log verbosity (-1 = silent, 0 = audit, 1 = control,\n"
					"                                    2 = controlmore, 3 = raw, 4 = private)\n"
					"\n"
		   );
	exit(msg == NULL? 0 : 1);
}

/**
 * Main function, manages the daemon.
 */
int main(int argc, char *argv[])
{
	bool use_syslog = FALSE;

	private_daemon_t *private_charon;
	FILE *pid_file;
	struct stat stb;
	level_t levels[DBG_MAX];
	int group;
	
	/* logging for library during initialization, as we have no bus yet */
	dbg = dbg_stderr;
	
	/* initialize library */
	library_init(STRONGSWAN_CONF);
	lib->printf_hook->add_handler(lib->printf_hook, 'R',
								  traffic_selector_printf_hook,
								  PRINTF_HOOK_ARGTYPE_POINTER,
								  PRINTF_HOOK_ARGTYPE_END);
	lib->printf_hook->add_handler(lib->printf_hook, 'P',
								  proposal_printf_hook,
								  PRINTF_HOOK_ARGTYPE_POINTER,
								  PRINTF_HOOK_ARGTYPE_END);
	private_charon = daemon_create();
	charon = (daemon_t*)private_charon;
	
	lookup_uid_gid(private_charon);
	
	/* use CTRL loglevel for default */
	for (group = 0; group < DBG_MAX; group++)
	{
		levels[group] = LEVEL_CTRL;
	}
	
	/* handle arguments */
	for (;;)
	{
		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "use-syslog", no_argument, NULL, 'l' },
			/* TODO: handle "debug-all" */
			{ "debug-dmn", required_argument, &group, DBG_DMN },
			{ "debug-mgr", required_argument, &group, DBG_MGR },
			{ "debug-ike", required_argument, &group, DBG_IKE },
			{ "debug-chd", required_argument, &group, DBG_CHD },
			{ "debug-job", required_argument, &group, DBG_JOB },
			{ "debug-cfg", required_argument, &group, DBG_CFG },
			{ "debug-knl", required_argument, &group, DBG_KNL },
			{ "debug-net", required_argument, &group, DBG_NET },
			{ "debug-enc", required_argument, &group, DBG_ENC },
			{ "debug-lib", required_argument, &group, DBG_LIB },
			{ 0,0,0,0 }
		};
		
		int c = getopt_long(argc, argv, "", long_opts, NULL);
		switch (c)
		{
			case EOF:
	    		break;
			case 'h':
				usage(NULL);
				break;
			case 'v':
				printf("Linux strongSwan %s\n", VERSION);
				exit(0);
			case 'l':
				use_syslog = TRUE;
				continue;
			case 0:
				/* option is in group */
				levels[group] = atoi(optarg);
				continue;
			default:
				usage("");
				break;
		}
		break;
	}
	
	/* initialize daemon */
	if (!initialize(private_charon, use_syslog, levels))
	{
		DBG1(DBG_DMN, "initialization failed - aborting charon");
		destroy(private_charon);
		exit(-1);
	}

	/* check/setup PID file */
	if (stat(PID_FILE, &stb) == 0)
	{
		DBG1(DBG_DMN, "charon already running (\""PID_FILE"\" exists)");
		destroy(private_charon);
		exit(-1);
	}
	pid_file = fopen(PID_FILE, "w");
	if (pid_file)
	{
		fprintf(pid_file, "%d\n", getpid());
		ignore_result(fchown(fileno(pid_file), charon->uid, charon->gid));
		fclose(pid_file);
	}
	
	/* drop the capabilities we won't need */
	drop_capabilities(private_charon);
	
	/* start the engine, go multithreaded */
	charon->processor->set_threads(charon->processor,
						lib->settings->get_int(lib->settings, "charon.threads",
											   DEFAULT_THREADS));
	
	/* run daemon */
	run(private_charon);
	
	/* normal termination, cleanup and exit */
	destroy(private_charon);
	unlink(PID_FILE);
	
	library_deinit();
	
	return 0;
}

