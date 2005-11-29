/**
 * @file daemon.c
 * 
 * @brief Main of IKEv2-Daemon
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

#include "daemon.h" 


#include <types.h>
#include <utils/allocator.h>
#include <queues/jobs/initiate_ike_sa_job.h>




typedef struct private_daemon_t private_daemon_t;

/**
 * Private additions to daemon_t, contains
 * threads and internal functions.
 */
struct private_daemon_t {
	/**
	 * public members of daemon_t
	 */
	daemon_t public;
	
	/**
	 * logger_t object assigned for daemon things
	 */
	logger_t *logger;

	/**
	 * Signal set used for signal handling
	 */
	sigset_t signal_set;
	
	void (*run) (private_daemon_t *this);
	void (*destroy) (private_daemon_t *this, char *reason);
	void (*build_test_jobs) (private_daemon_t *this);
	void (*initialize) (private_daemon_t *this);
	void (*cleanup) (private_daemon_t *this);
};



/** 
 * instance of the daemon 
 */
daemon_t *charon;



/**
 * Loop of the main thread, waits for signals
 */
static void run(private_daemon_t *this)
{	
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
				this->logger->log(this->logger, CONTROL, "Signal of type SIGINT received. Exit main loop.");
				return;
			}
			case SIGTERM:
				this->logger->log(this->logger, CONTROL, "Signal of type SIGTERM received. Exit main loop.");
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
 * Initialize the destruction of the daemon
 */
static void destroy(private_daemon_t *this, char *reason)
{
	/* we send SIGTERM, so the daemon can cleanly shut down */
	this->logger->log(this->logger, ERROR, "Killing daemon: %s", reason);
	this->logger->log(this->logger, CONTROL, "sending SIGTERM to ourself", reason);
	kill(0, SIGTERM);
	/* thread must die, since he produced a ciritcal failure and can't continue */
	pthread_exit(NULL);
}

/**
 * build some jobs to test daemon functionality
 */
static void build_test_jobs(daemon_t *this)
{
	int i;
	for(i = 0; i<1; i++)
	{
		initiate_ike_sa_job_t *initiate_job;
		initiate_job = initiate_ike_sa_job_create("localhost");
		this->job_queue->add(this->job_queue, (job_t*)initiate_job);
	}
}


/**
 * Initialize global objects and threads
 */
static void initialize(daemon_t *this)
{
	this->socket = socket_create(IKEV2_UDP_PORT);
	this->ike_sa_manager = ike_sa_manager_create();
	this->job_queue = job_queue_create();
	this->event_queue = event_queue_create();
	this->send_queue = send_queue_create();
	this->configuration_manager = configuration_manager_create();
	
	this->sender = sender_create();
	this->receiver = receiver_create();
	this->scheduler = scheduler_create();
	this->thread_pool = thread_pool_create(NUMBER_OF_WORKING_THREADS);	
}

/**
 * Destory all initiated objects
 */
static void cleanup(daemon_t *this)
{
	if (this->receiver != NULL)
	{
		this->receiver->destroy(this->receiver);
	}
	if (this->scheduler != NULL)
	{
		this->scheduler->destroy(this->scheduler);	
	}
	if (this->sender != NULL)
	{
		this->sender->destroy(this->sender);
	}
	if (this->thread_pool != NULL)
	{
		this->thread_pool->destroy(this->thread_pool);	
	}
	if (this->job_queue != NULL)
	{
		this->job_queue->destroy(this->job_queue);
	}
	if (this->event_queue != NULL)
	{
		this->event_queue->destroy(this->event_queue);	
	}
	if (this->send_queue != NULL)
	{
		this->send_queue->destroy(this->send_queue);	
	}
	if (this->socket != NULL)
	{
		this->socket->destroy(this->socket);
	}
	if (this->ike_sa_manager != NULL)
	{
		this->ike_sa_manager->destroy(this->ike_sa_manager);
	}
	if (this->configuration_manager != NULL)
	{
		this->configuration_manager->destroy(this->configuration_manager);
	}
	
	this->logger_manager->destroy(this->logger_manager);
	allocator_free(this);
}



/**
 * @brief Create the daemon.
 * 
 * @return 	created daemon_t
 */
private_daemon_t *daemon_create()
{
	private_daemon_t *this = allocator_alloc_thing(private_daemon_t);
		
	/* assign methods */
	this->run = run;
	this->public.destroy = (void (*) (daemon_t*,char*))destroy;
	this->build_test_jobs = (void (*) (private_daemon_t*)) build_test_jobs;
	this->initialize = (void (*) (private_daemon_t*))initialize;
	this->cleanup = (void (*) (private_daemon_t*))cleanup;
	
	/* first build a logger */
	this->public.logger_manager = logger_manager_create(DEFAULT_LOGLEVEL);
	this->logger = (this->public.logger_manager)->create_logger(this->public.logger_manager, DAEMON, NULL);
	
	/* NULL members for clean destruction */
	this->public.socket = NULL;
	this->public.ike_sa_manager = NULL;
	this->public.job_queue = NULL;
	this->public.event_queue = NULL;
	this->public.send_queue = NULL;
	this->public.configuration_manager = NULL;
	this->public.sender= NULL;
	this->public.receiver = NULL;
	this->public.scheduler = NULL;
	this->public.thread_pool = NULL;
	
	/* setup signal handling */
	sigemptyset(&(this->signal_set));
	sigaddset(&(this->signal_set), SIGINT); 
	sigaddset(&(this->signal_set), SIGHUP); 
	sigaddset(&(this->signal_set), SIGTERM); 
	pthread_sigmask(SIG_BLOCK, &(this->signal_set), 0);
	
	return this;
}

/**
 * Main function, manages the daemon
 */
int main(int argc, char *argv[])
{
	private_daemon_t *private_charon;
	
	private_charon = daemon_create();
	charon = (daemon_t*)private_charon;
	
	private_charon->initialize(private_charon);
	
	private_charon->build_test_jobs(private_charon);
	
	private_charon->run(private_charon);
	
	private_charon->cleanup(private_charon);
	
#ifdef LEAK_DETECTIVE
	report_memory_leaks(void);
#endif

	return 0;
}

