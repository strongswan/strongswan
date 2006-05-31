/**
 * @file daemon.c
 * 
 * @brief Implementation of daemon_t and main of IKEv2-Daemon.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
#include <execinfo.h>
#include <string.h>

#include "daemon.h" 

#include <types.h>
#include <config/connections/local_connection_store.h>
#include <config/credentials/local_credential_store.h>
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
	 * @param this 	calling object
	 */
	void (*initialize) (private_daemon_t *this);
	
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
		kill(0, SIGTERM);
		/* thread must die, since he produced a ciritcal failure and can't continue */
		pthread_exit(NULL);
	}
}

/**
 * Implementation of private_daemon_t.initialize.
 */
static void initialize(private_daemon_t *this)
{
	local_credential_store_t* cred_store;
	
	this->public.configuration = configuration_create();
	this->public.socket = socket_create(IKEV2_UDP_PORT);
	this->public.ike_sa_manager = ike_sa_manager_create();
	this->public.job_queue = job_queue_create();
	this->public.event_queue = event_queue_create();
	this->public.send_queue = send_queue_create();
	this->public.connections = (connection_store_t*)local_connection_store_create();
	this->public.policies = (policy_store_t*)local_policy_store_create();
	this->public.credentials = (credential_store_t*)(cred_store = local_credential_store_create());
	
	/* load keys & certs */
	cred_store->load_ca_certificates(cred_store, CA_CERTIFICATE_DIR);
	cred_store->load_private_keys(cred_store, SECRETS_FILE, PRIVATE_KEY_DIR);
	
	
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
	if (this->public.receiver != NULL)
	{	/* we don't want to receive anything... */
		this->public.receiver->destroy(this->public.receiver);
	}
	if (this->public.stroke != NULL)
	{	/* ignore all incoming user requests */
		this->public.stroke->destroy(this->public.stroke);
	}
	if (this->public.scheduler != NULL)
	{	/* stop scheduing jobs */
		this->public.scheduler->destroy(this->public.scheduler);	
	}
	if (this->public.thread_pool != NULL)
	{	/* stop processing jobs */
		this->public.thread_pool->destroy(this->public.thread_pool);	
	}
	if (this->public.ike_sa_manager != NULL)
	{	/* shut down manager with all IKE SAs */
		this->public.ike_sa_manager->destroy(this->public.ike_sa_manager);
	}
	if (this->public.kernel_interface != NULL)
	{	/* all child SAs should be down now, so kill kernel interface */
		this->public.kernel_interface->destroy(this->public.kernel_interface);
	}
	/* destroy other infrastructure */
	if (this->public.job_queue != NULL)
	{
		this->public.job_queue->destroy(this->public.job_queue);
	}
	if (this->public.event_queue != NULL)
	{
		this->public.event_queue->destroy(this->public.event_queue);	
	}
	if (this->public.configuration != NULL)
	{
		this->public.configuration->destroy(this->public.configuration);
	}
	if (this->public.credentials != NULL)
	{
		this->public.credentials->destroy(this->public.credentials);
	}
	if (this->public.connections != NULL)
	{
		this->public.connections->destroy(this->public.connections);
	}
	if (this->public.policies != NULL)
	{
		this->public.policies->destroy(this->public.policies);
	}
	/* we hope the sender could send the outstanding deletes, but 
	 * we shut down here at any cost */
	if (this->public.sender != NULL)
	{
		this->public.sender->destroy(this->public.sender);
	}
	if (this->public.send_queue != NULL)
	{
		this->public.send_queue->destroy(this->public.send_queue);	
	}
	if (this->public.socket != NULL)
	{
		this->public.socket->destroy(this->public.socket);
	}
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

	logger->log(logger, ERROR, "Thread %u received SIGSEGV. Dumping %d frames from stack:", pthread_self(), size);

	for (i = 0; i < size; i++)
	{
		logger->log(logger, ERROR, "    %s", strings[i]);
	}
	free (strings);
	logger->log(logger, ERROR, "Killing ourself hard after SIGSEGV");
	kill(getpid(), SIGKILL);
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
	return this;
}

/**
 * Main function, manages the daemon.
 */
int main(int argc, char *argv[])
{	
	private_daemon_t *private_charon;
	FILE *pid_file;
	struct stat stb;
	int i;
	
	/* trivial argument parsing */
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--use-syslog") == 0)
		{
			logger_manager->set_output(logger_manager, ALL_LOGGERS, NULL);
		}
	}
	private_charon = daemon_create();
	charon = (daemon_t*)private_charon;
	
	private_charon->logger = logger_manager->get_logger(logger_manager, DAEMON);

	private_charon->logger->log(private_charon->logger, CONTROL, 
								"Starting Charon (strongSwan Version %s)", VERSION);
		
	/* initialize daemon */
	private_charon->initialize(private_charon);
	
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
	
	/* run daemon */
	private_charon->run(private_charon);
	
	/* normal termination, cleanup and exit */
	private_charon->destroy(private_charon);
	unlink(PID_FILE);

	return 0;
}


