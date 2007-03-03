/**
 * @file daemon.c
 * 
 * @brief Implementation of daemon_t and main of IKEv2-Daemon.
 * 
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
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
#include <config/credentials/local_credential_store.h>
#include <config/connections/local_connection_store.h>
#include <config/policies/local_policy_store.h>
#include <sa/authenticators/eap/eap_method.h>


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
	/* reselect signals for this thread */
	sigemptyset(&(this->signal_set));
	sigaddset(&(this->signal_set), SIGINT); 
	sigaddset(&(this->signal_set), SIGHUP); 
	sigaddset(&(this->signal_set), SIGTERM); 
	pthread_sigmask(SIG_BLOCK, &(this->signal_set), 0);
	
	while(TRUE)
	{
		int signal_number;
		int error;
		
		error = sigwait(&(this->signal_set), &signal_number);
		if(error)
		{
			DBG1(DBG_DMN, "error %d while waiting for a signal", error);
			return;
		}
		switch (signal_number)
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
				DBG1(DBG_DMN, "signal of type SIGTERM received. Shutting down");
				return;
			default:
			{
				DBG1(DBG_DMN, "unknown signal %d received. Ignored", signal_number);
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
	/* destruction is a non trivial task, we need to follow 
	* a strict order to prevent threading issues! 
	* Kill active threads first, except the sender, as
	* the killed IKE_SA want to send delete messages.
	*/
	/* we don't want to receive anything anymore... */
	DESTROY_IF(this->public.receiver);
	/* ignore all incoming user requests */
	DESTROY_IF(this->public.stroke);
	/* stop scheduing jobs */
	DESTROY_IF(this->public.scheduler);
	/* stop processing jobs */
	DESTROY_IF(this->public.thread_pool);
	/* shut down manager with all IKE SAs */
	DESTROY_IF(this->public.ike_sa_manager);
	/* all child SAs should be down now, so kill kernel interface */
	DESTROY_IF(this->public.kernel_interface);
	/* destroy other infrastructure */
	DESTROY_IF(this->public.job_queue);
	DESTROY_IF(this->public.event_queue);
	DESTROY_IF(this->public.configuration);
	DESTROY_IF(this->public.credentials);
	DESTROY_IF(this->public.connections);
	DESTROY_IF(this->public.policies);
	sched_yield();
	/* we hope the sender could send the outstanding deletes, but 
	 * we shut down here at any cost */
	DESTROY_IF(this->public.sender);
	DESTROY_IF(this->public.send_queue);
	DESTROY_IF(this->public.socket);
	/* before destroying bus with its listeners, rehook library logs */
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
 * Initialize the daemon, optional with a strict crl policy
 */
static void initialize(private_daemon_t *this, bool strict, bool syslog,
					   level_t levels[])
{
	credential_store_t* credentials;
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
		if (syslog)
		{
			this->public.syslog->set_level(this->public.syslog,
										   signal, levels[signal]);
		}
		else
		{
			this->public.outlog->set_level(this->public.outlog,
										   signal, levels[signal]);
		}
	}
	
	DBG1(DBG_DMN, "starting charon (strongSwan Version %s)", VERSION);
	
	this->public.configuration = configuration_create();
	this->public.socket = socket_create(IKEV2_UDP_PORT, IKEV2_NATT_PORT);
	this->public.ike_sa_manager = ike_sa_manager_create();
	this->public.job_queue = job_queue_create();
	this->public.event_queue = event_queue_create();
	this->public.send_queue = send_queue_create();
	this->public.connections = (connection_store_t*)local_connection_store_create();
	this->public.policies = (policy_store_t*)local_policy_store_create();
	this->public.credentials = (credential_store_t*)local_credential_store_create(strict);

	/* load secrets, ca certificates and crls */
	credentials = this->public.credentials;
	credentials->load_ca_certificates(credentials);
	credentials->load_crls(credentials);
	credentials->load_secrets(credentials);
	
	/* start building threads, we are multi-threaded NOW */
	this->public.stroke = stroke_create();
	this->public.sender = sender_create();
	this->public.receiver = receiver_create();
	this->public.scheduler = scheduler_create();
	this->public.kernel_interface = kernel_interface_create();
	this->public.thread_pool = thread_pool_create(NUMBER_OF_WORKING_THREADS);
}

/**
 * Handle SIGSEGV/SIGILL signals raised by threads
 */
void signal_handler(int signal)
{
#ifdef HAVE_BACKTRACE
	void *array[20];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace(array, 20);
	strings = backtrace_symbols(array, size);

	DBG1(DBG_DMN, "thread %u received %s. Dumping %d frames from stack:",
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
	DBG1(DBG_DMN, "killing ourself hard after SIGSEGV");
	raise(SIGKILL);
}

/**
 * Create the daemon.
 */
private_daemon_t *daemon_create(void)
{	
	private_daemon_t *this = malloc_thing(private_daemon_t);
	struct sigaction action;
		
	/* assign methods */
	this->public.kill = (void (*) (daemon_t*,char*))kill_daemon;
	
	/* NULL members for clean destruction */
	this->public.socket = NULL;
	this->public.ike_sa_manager = NULL;
	this->public.job_queue = NULL;
	this->public.event_queue = NULL;
	this->public.send_queue = NULL;
	this->public.configuration = NULL;
	this->public.credentials = NULL;
	this->public.connections = NULL;
	this->public.policies = NULL;
	this->public.sender= NULL;
	this->public.receiver = NULL;
	this->public.scheduler = NULL;
	this->public.kernel_interface = NULL;
	this->public.thread_pool = NULL;
	this->public.stroke = NULL;
	this->public.bus = NULL;
	this->public.outlog = NULL;
	this->public.syslog = NULL;
	this->public.authlog = NULL;
	
	this->main_thread_id = pthread_self();
	
	/* setup signal handling for all threads */
	sigemptyset(&(this->signal_set));
	sigaddset(&(this->signal_set), SIGSEGV);
	sigaddset(&(this->signal_set), SIGINT); 
	sigaddset(&(this->signal_set), SIGHUP); 
	sigaddset(&(this->signal_set), SIGTERM); 
	pthread_sigmask(SIG_BLOCK, &(this->signal_set), 0);
	
	/* setup SIGSEGV handler for all threads */
	action.sa_handler = signal_handler;
	action.sa_mask = this->signal_set;
	action.sa_flags = 0;
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGILL, &action, NULL);
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
	bool strict_crl_policy = FALSE;
	bool use_syslog = FALSE;
	char *eapdir = IPSEC_EAPDIR;

	private_daemon_t *private_charon;
	FILE *pid_file;
	struct stat stb;
	linked_list_t *list;
	host_t *host;
	level_t levels[DBG_MAX];
	int signal;
	
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
			{ "strictcrlpolicy", no_argument, NULL, 'r' },
			{ "eapdir", required_argument, NULL, 'e' },
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
			case 'r':
				strict_crl_policy = TRUE;
				continue;
			case 'e':
				eapdir = optarg;
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

	private_charon = daemon_create();
	charon = (daemon_t*)private_charon;
	
	/* initialize daemon */
	initialize(private_charon, strict_crl_policy, use_syslog, levels);
	/* load pluggable EAP modules */
	eap_method_load(eapdir);
	
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
		fclose(pid_file);
	}
	
	/* log socket info */
	list = charon->kernel_interface->create_address_list(charon->kernel_interface);
	DBG1(DBG_NET, "listening on %d addresses:", list->get_count(list));
	while (list->remove_first(list, (void**)&host) == SUCCESS)
	{
		DBG1(DBG_NET, "  %H", host);
		host->destroy(host);
	}
	list->destroy(list);
	
	/* run daemon */
	run(private_charon);
	
	eap_method_unload();
	/* normal termination, cleanup and exit */
	destroy(private_charon);
	unlink(PID_FILE);
	
	return 0;
}
