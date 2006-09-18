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
#include <execinfo.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "daemon.h" 

#include <types.h>
#include <config/credentials/local_credential_store.h>
#include <config/connections/local_connection_store.h>
#include <config/policies/local_policy_store.h>


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
	 * A logger_t object assigned for daemon things.
	 */
	logger_t *logger;

	/**
	 * Signal set used for signal handling.
	 */
	sigset_t signal_set;
	
	/** 
	 * The thread_id of main-thread.
	 */
	pthread_t main_thread_id;
	
	/**
	 * Main loop function.
	 * 
	 * @param this 	calling object
	 */
	void (*run) (private_daemon_t *this);
	
	/**
	 * Initialize the daemon.
	 * 
	 * @param this		calling object
	 * @param strict	enforce a strict crl policy
	 */
	void (*initialize) (private_daemon_t *this, bool strict);
	
	/**
	 * Destroy the daemon.
	 * 
	 * @param this 	calling object
	 */
	void (*destroy) (private_daemon_t *this);
};

/** 
 * One and only instance of the daemon.
 */
daemon_t *charon;

/**
 * Implementation of private_daemon_t.run.
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
			this->logger->log(this->logger, ERROR, "Error %d when waiting for signal", error);
			return;
		}
		switch (signal_number)
		{
			case SIGHUP:
			{
				this->logger->log(this->logger, CONTROL, "Signal of type SIGHUP received. Do nothing");
				break;
			}
			case SIGINT:
			{
				this->logger->log(this->logger, CONTROL, "Signal of type SIGINT received. Exit main loop");
				return;
			}
			case SIGTERM:
				this->logger->log(this->logger, CONTROL, "Signal of type SIGTERM received. Exit main loop");
				return;
			default:
			{
				this->logger->log(this->logger, CONTROL, "Unknown signal %d received. Do nothing", signal_number);
				break;
			}
		}
	}
}

/**
 * Implementation of daemon_t.kill.
 */
static void kill_daemon(private_daemon_t *this, char *reason)
{
	/* we send SIGTERM, so the daemon can cleanly shut down */
	this->logger->log(this->logger, CONTROL, "Killing daemon: %s", reason);
	if (this->main_thread_id == pthread_self())
	{
		/* initialization failed, terminate daemon */
		this->destroy(this);
		unlink(PID_FILE);
		exit(-1);
	}
	else
	{
		this->logger->log(this->logger, CONTROL, "sending SIGTERM to ourself", reason);
		raise(SIGTERM);
		/* thread must die, since he produced a ciritcal failure and can't continue */
		pthread_exit(NULL);
	}
}

/**
 * Implementation of private_daemon_t.initialize.
 */
static void initialize(private_daemon_t *this, bool strict)
{
	credential_store_t* credentials;
	
	/* for uncritical pseudo random numbers */
	srandom(time(NULL) + getpid());
	
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
 * Destory all initiated objects
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
	/* we hope the sender could send the outstanding deletes, but 
	 * we shut down here at any cost */
	DESTROY_IF(this->public.sender);
	DESTROY_IF(this->public.send_queue);
	DESTROY_IF(this->public.socket);
	free(this);
}

void signal_handler(int signal)
{
	void *array[20];
	size_t size;
	char **strings;
	size_t i;
	logger_t *logger;

	size = backtrace(array, 20);
	strings = backtrace_symbols(array, size);
	logger = logger_manager->get_logger(logger_manager, DAEMON);

	logger->log(logger, ERROR, 
				"Thread %u received %s. Dumping %d frames from stack:",
				signal == SIGSEGV ? "SIGSEGV" : "SIGILL",
				pthread_self(), size);

	for (i = 0; i < size; i++)
	{
		logger->log(logger, ERROR, "    %s", strings[i]);
	}
	free (strings);
	logger->log(logger, ERROR, "Killing ourself hard after SIGSEGV");
	raise(SIGKILL);
}

/**
 * @brief Create the daemon.
 * 
 * @return 	created daemon_t
 */
private_daemon_t *daemon_create(void)
{	
	private_daemon_t *this = malloc_thing(private_daemon_t);
	struct sigaction action;
		
	/* assign methods */
	this->run = run;
	this->destroy = destroy;
	this->initialize = initialize;
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
	if (sigaction(SIGSEGV, &action, NULL) == -1)
	{
		this->logger->log(this->logger, ERROR, "signal handler setup for SIGSEGV failed");
	}
	if (sigaction(SIGILL, &action, NULL) == -1)
	{
		this->logger->log(this->logger, ERROR, "signal handler setup for SIGILL failed");
	}
	return this;
}

static void usage(const char *msg)
{
	if (msg != NULL && *msg != '\0')
		fprintf(stderr, "%s\n", msg);
    fprintf(stderr, "Usage: charon"
		" [--help]"
		" [--version]"
		" [--use-syslog]"
		" [--strictcrlpolicy]"
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

	private_daemon_t *private_charon;
	FILE *pid_file;
	struct stat stb;
	linked_list_t *list;
	host_t *host;
	
    /* handle arguments */
    for (;;)
    {
		static const struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "version", no_argument, NULL, 'v' },
			{ "use-syslog", no_argument, NULL, 'l' },
			{ "strictcrlpolicy", no_argument, NULL, 'r' },
			{ 0,0,0,0 }
		};

		int c = getopt_long(argc, argv, "", long_opts, NULL);

		/* Note: "breaking" from case terminates loop */
		switch (c)
		{
			case EOF:	/* end of flags */
	    		break;
			case 'h':
				usage(NULL);
				break;	/* not actually reached */
			case 'v':
				printf("Linux strongSwan %s\n", VERSION);
				exit(0);
			case 'l':
				logger_manager->set_output(logger_manager, ALL_LOGGERS, NULL);
				continue;
			case 'r':
				strict_crl_policy = TRUE;
				continue;
			default:
				usage("");
				break;	/* not actually reached */
		}
		break;
	}

	private_charon = daemon_create();
	charon = (daemon_t*)private_charon;
	
	private_charon->logger = logger_manager->get_logger(logger_manager, DAEMON);

	private_charon->logger->log(private_charon->logger, CONTROL, 
								"Starting Charon (strongSwan Version %s)", VERSION);
		
	/* initialize daemon */
	private_charon->initialize(private_charon, strict_crl_policy);
	
	/* check/setup PID file */
	if (stat(PID_FILE, &stb) == 0)
	{
		private_charon->logger->log(private_charon->logger, ERROR, 
									"charon already running (\""PID_FILE"\" exists)");
		private_charon->destroy(private_charon);
		exit(-1);
	}
	pid_file = fopen(PID_FILE, "w");
	if (pid_file)
	{
		fprintf(pid_file, "%d\n", getpid());
		fclose(pid_file);
	}
	/* log socket info */
	list = charon->socket->create_local_address_list(charon->socket);
	private_charon->logger->log(private_charon->logger, CONTROL,
								"listening on %d addresses:",
								list->get_count(list));
	while (list->remove_first(list, (void**)&host) == SUCCESS)
	{
		private_charon->logger->log(private_charon->logger, CONTROL,
									"  %s", host->get_string(host));
		host->destroy(host);
	}
	list->destroy(list);
	
	/* run daemon */
	private_charon->run(private_charon);
	
	/* normal termination, cleanup and exit */
	private_charon->destroy(private_charon);
	unlink(PID_FILE);

	return 0;
}


