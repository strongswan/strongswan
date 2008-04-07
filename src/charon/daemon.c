/* 
 * Copyright (C) 2006-2007 Tobias Brunner
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
#include <linux/capability.h>
#include <sys/prctl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#ifdef HAVE_BACKTRACE
# include <execinfo.h>
#endif /* HAVE_BACKTRACE */

#include "daemon.h"

#include <library.h>
#include <credentials/credential_manager.h>
#include <config/backend_manager.h>
#include <config/traffic_selector.h>

/* on some distros, a capset definition is missing */
#ifdef NO_CAPSET_DEFINED
extern int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
#endif /* NO_CAPSET_DEFINED */

#ifdef INTEGRITY_TEST
#include <fips/fips.h>
#include <fips_signature.h>
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
	
	/** 
	 * The thread_id of main-thread.
	 */
	pthread_t main_thread_id;
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
	charon->bus->vsignal(charon->bus, DBG_LIB, level, fmt, args);
	va_end(args);
}
/**
 * Logging hook for library logs before logging facility initiated
 */
static void dbg_silent(int level, char *fmt, ...)
{
}

/**
 * Logging hook for library logs, using stderr output
 */
static void dbg_stderr(int level, char *fmt, ...)
{
	va_list args;
	
	va_start(args, fmt);
	fprintf(stderr, "00[LIB] ");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
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
	DESTROY_IF(this->public.plugins);
	DESTROY_IF(this->public.ike_sa_manager);
	DESTROY_IF(this->public.kernel_interface);
	DESTROY_IF(this->public.scheduler);
	DESTROY_IF(this->public.controller);
	DESTROY_IF(this->public.eap);
#ifdef ME
	DESTROY_IF(this->public.connect_manager);
	DESTROY_IF(this->public.mediation_manager);
#endif /* ME */
	DESTROY_IF(this->public.backends);
	DESTROY_IF(this->public.credentials);
	DESTROY_IF(this->public.sender);
	DESTROY_IF(this->public.receiver);
	DESTROY_IF(this->public.socket);
	/* wait until all threads are gone */
	DESTROY_IF(this->public.processor);
	
	/* rehook library logging, shutdown logging */
	dbg = dbg_stderr;
	DESTROY_IF(this->public.bus);
	DESTROY_IF(this->public.outlog);
	DESTROY_IF(this->public.syslog);
	DESTROY_IF(this->public.authlog);
	free(this);
}

/**
 * Enforce daemon shutdown, with a given reason to do so.
 */
static void kill_daemon(private_daemon_t *this, char *reason)
{
	/* we send SIGTERM, so the daemon can cleanly shut down */
	DBG1(DBG_DMN, "killing daemon: %s", reason);
	if (this->main_thread_id == pthread_self())
	{
		/* initialization failed, terminate daemon */
		destroy(this);
		unlink(PID_FILE);
		exit(-1);
	}
	else
	{
		DBG1(DBG_DMN, "sending SIGTERM to ourself");
		raise(SIGTERM);
		/* thread must die, since he produced a ciritcal failure and can't continue */
		pthread_exit(NULL);
	}
}

/**
 * drop daemon capabilities
 */
static void drop_capabilities(private_daemon_t *this, bool full)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data;
	
	/* CAP_NET_ADMIN is needed to use netlink */
	u_int32_t keep = (1<<CAP_NET_ADMIN) | (1<<CAP_SYS_NICE);
	
	if (full)
	{
#		if IPSEC_GID
		if (setgid(IPSEC_GID) != 0)
		{
			kill_daemon(this, "changing GID to unprivileged group failed");
		}
#		endif
#		if IPSEC_UID
		if (setuid(IPSEC_UID) != 0)
		{
			kill_daemon(this, "changing UID to unprivileged user failed");
		}
#		endif
	}
	else
	{
		/* CAP_NET_BIND_SERVICE to bind services below port 1024 */
		keep |= (1<<CAP_NET_BIND_SERVICE);
		/* CAP_NET_RAW to create RAW sockets */
		keep |= (1<<CAP_NET_RAW);
		/* CAP_DAC_READ_SEARCH to read ipsec.secrets */
		keep |= (1<<CAP_DAC_READ_SEARCH);
		/* CAP_CHOWN to change file permissions (socket permissions) */
		keep |= (1<<CAP_CHOWN);
		/* CAP_SETUID to call setuid()  */
		keep |= (1<<CAP_SETUID);
		/* CAP_SETGID to call setgid() */
		keep |= (1<<CAP_SETGID);
	}

	hdr.version = _LINUX_CAPABILITY_VERSION;
	hdr.pid = 0;
	data.inheritable = data.effective = data.permitted = keep;
	
	if (capset(&hdr, &data))
	{
		kill_daemon(this, "unable to drop daemon capabilities");
	}
}

/**
 * Initialize the daemon
 */
static bool initialize(private_daemon_t *this, bool syslog, level_t levels[])
{
	signal_t signal;
	
	/* for uncritical pseudo random numbers */
	srandom(time(NULL) + getpid());
	
	/* setup bus and it's listeners first to enable log output */
	this->public.bus = bus_create();
	this->public.outlog = file_logger_create(stdout);
	this->public.syslog = sys_logger_create(LOG_DAEMON);
	this->public.authlog = sys_logger_create(LOG_AUTHPRIV);
	this->public.bus->add_listener(this->public.bus, &this->public.syslog->listener);
	this->public.bus->add_listener(this->public.bus, &this->public.outlog->listener);
	this->public.bus->add_listener(this->public.bus, &this->public.authlog->listener);
	this->public.authlog->set_level(this->public.authlog, SIG_ANY, LEVEL_AUDIT);
	/* set up hook to log dbg message in library via charons message bus */
	dbg = dbg_bus;
	
	/* apply loglevels */
	for (signal = 0; signal < DBG_MAX; signal++)
	{
		this->public.syslog->set_level(this->public.syslog,
									   signal, levels[signal]);
		if (!syslog)
		{
			this->public.outlog->set_level(this->public.outlog,
										   signal, levels[signal]);
		}
	}
	
	DBG1(DBG_DMN, "starting charon (strongSwan Version %s)", VERSION);

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
	this->public.processor = processor_create();
	this->public.scheduler = scheduler_create();

	/* load secrets, ca certificates and crls */
	this->public.credentials = credential_manager_create();
	this->public.controller = controller_create();
	this->public.eap = eap_manager_create();
	this->public.backends = backend_manager_create();
	this->public.plugins = plugin_loader_create();
	this->public.kernel_interface = kernel_interface_create();
	this->public.socket = socket_create();
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

	this->public.plugins->load(this->public.plugins, IPSEC_PLUGINDIR, "libcharon-");
	
	return TRUE;
}

/**
 * Handle SIGSEGV/SIGILL signals raised by threads
 */
static void segv_handler(int signal)
{
#ifdef HAVE_BACKTRACE
	void *array[20];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace(array, 20);
	strings = backtrace_symbols(array, size);

	DBG1(DBG_JOB, "thread %u received %s. Dumping %d frames from stack:",
		 pthread_self(), signal == SIGSEGV ? "SIGSEGV" : "SIGILL", size);

	for (i = 0; i < size; i++)
	{
		DBG1(DBG_DMN, "    %s", strings[i]);
	}
	free (strings);
#else /* !HAVE_BACKTRACE */
	DBG1(DBG_DMN, "thread %u received %s",
		 pthread_self(), signal == SIGSEGV ? "SIGSEGV" : "SIGILL");
#endif /* HAVE_BACKTRACE */
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
	
	/* NULL members for clean destruction */
	this->public.socket = NULL;
	this->public.ike_sa_manager = NULL;
	this->public.credentials = NULL;
	this->public.backends = NULL;
	this->public.sender= NULL;
	this->public.receiver = NULL;
	this->public.scheduler = NULL;
	this->public.kernel_interface = NULL;
	this->public.processor = NULL;
	this->public.controller = NULL;
	this->public.eap = NULL;
	this->public.plugins = NULL;
	this->public.bus = NULL;
	this->public.outlog = NULL;
	this->public.syslog = NULL;
	this->public.authlog = NULL;
	
	this->main_thread_id = pthread_self();
	
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
					"         [--strictcrlpolicy]\n"
					"         [--cachecrls]\n"
					"         [--crlcheckinterval <interval>]\n"
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
	u_int crl_check_interval = 0;
	bool cache_crls = FALSE;
	bool use_syslog = FALSE;

	private_daemon_t *private_charon;
	FILE *pid_file;
	struct stat stb;
	level_t levels[DBG_MAX];
	int signal;
	
	/* silence the library during initialization, as we have no bus yet */
	dbg = dbg_silent;
	
	/* initialize library */
	library_init(STRONGSWAN_CONF);
	lib->plugins->load(lib->plugins, IPSEC_PLUGINDIR, "libstrongswan-");
	lib->printf_hook->add_handler(lib->printf_hook, 'R',
								  traffic_selector_get_printf_hooks());
	private_charon = daemon_create();
	charon = (daemon_t*)private_charon;
	
	/* drop the capabilities we won't need for initialization */
	prctl(PR_SET_KEEPCAPS, 1);
	drop_capabilities(private_charon, FALSE);
	
	/* use CTRL loglevel for default */
	for (signal = 0; signal < DBG_MAX; signal++)
	{
		levels[signal] = LEVEL_CTRL;
	}
	
	/* handle arguments */
	for (;;)
	{
		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "use-syslog", no_argument, NULL, 'l' },
			{ "cachecrls", no_argument, NULL, 'C' },
			{ "crlcheckinterval", required_argument, NULL, 'x' },
			/* TODO: handle "debug-all" */
			{ "debug-dmn", required_argument, &signal, DBG_DMN },
			{ "debug-mgr", required_argument, &signal, DBG_MGR },
			{ "debug-ike", required_argument, &signal, DBG_IKE },
			{ "debug-chd", required_argument, &signal, DBG_CHD },
			{ "debug-job", required_argument, &signal, DBG_JOB },
			{ "debug-cfg", required_argument, &signal, DBG_CFG },
			{ "debug-knl", required_argument, &signal, DBG_KNL },
			{ "debug-net", required_argument, &signal, DBG_NET },
			{ "debug-enc", required_argument, &signal, DBG_ENC },
			{ "debug-lib", required_argument, &signal, DBG_LIB },
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
			case 'C':
				cache_crls = TRUE;
				continue;
			case 'x':
				crl_check_interval = atoi(optarg);
				continue;
			case 0:
				/* option is in signal */
				levels[signal] = atoi(optarg);
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
		fchown(fileno(pid_file), IPSEC_UID, IPSEC_GID);
		fclose(pid_file);
	}
	
	/* drop additional capabilites (bind & root) */
	drop_capabilities(private_charon, TRUE);
	
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

