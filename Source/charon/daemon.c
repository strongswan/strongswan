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

#include "daemon.h" 

#include <types.h>
#include <utils/allocator.h>
#include <queues/jobs/initiate_ike_sa_job.h>


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
	 * A routine to add jobs for testing.
	 * 
	 * @param this 	calling object
	 */
	void (*build_test_jobs) (private_daemon_t *this);
	
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
 * Implementation of private_daemon_t.build_test_jobs.
 */
static void build_test_jobs(private_daemon_t *this)
{
	int i;
	for(i = 0; i<1; i++)
	{
		initiate_ike_sa_job_t *initiate_job;
		initiate_job = initiate_ike_sa_job_create("localhost");
		this->public.event_queue->add_relative(this->public.event_queue, (job_t*)initiate_job, i * 5000);
	}
}

/**
 * Implementation of private_daemon_t.initialize.
 */
static void initialize(private_daemon_t *this)
{
	this->public.socket = socket_create(IKEV2_UDP_PORT);
	this->public.ike_sa_manager = ike_sa_manager_create();
	this->public.job_queue = job_queue_create();
	this->public.event_queue = event_queue_create();
	this->public.send_queue = send_queue_create();
	this->public.configuration_manager = configuration_manager_create(RETRANSMIT_TIMEOUT,MAX_RETRANSMIT_COUNT, HALF_OPEN_IKE_SA_TIMEOUT);
	
	this->public.sender = sender_create();
	this->public.receiver = receiver_create();
	this->public.scheduler = scheduler_create();
	this->public.prime_pool = prime_pool_create(PRIME_PRE_COMPUTATION_LIMIT);
	this->public.thread_pool = thread_pool_create(NUMBER_OF_WORKING_THREADS);	
}

/**
 * Destory all initiated objects
 */
static void destroy(private_daemon_t *this)
{
	if (this->public.receiver != NULL)
	{
		this->public.receiver->destroy(this->public.receiver);
	}
	if (this->public.scheduler != NULL)
	{
		this->public.scheduler->destroy(this->public.scheduler);	
	}
	if (this->public.sender != NULL)
	{
		this->public.sender->destroy(this->public.sender);
	}
	if (this->public.thread_pool != NULL)
	{
		this->public.thread_pool->destroy(this->public.thread_pool);	
	}
	if (this->public.prime_pool != NULL)
	{
		this->public.prime_pool->destroy(this->public.prime_pool);	
	}
	if (this->public.job_queue != NULL)
	{
		this->public.job_queue->destroy(this->public.job_queue);
	}
	if (this->public.event_queue != NULL)
	{
		this->public.event_queue->destroy(this->public.event_queue);	
	}
	if (this->public.send_queue != NULL)
	{
		this->public.send_queue->destroy(this->public.send_queue);	
	}
	if (this->public.socket != NULL)
	{
		this->public.socket->destroy(this->public.socket);
	}
	if (this->public.ike_sa_manager != NULL)
	{
		this->public.ike_sa_manager->destroy(this->public.ike_sa_manager);
	}
	if (this->public.configuration_manager != NULL)
	{
		this->public.configuration_manager->destroy(this->public.configuration_manager);
	}
	
	this->public.logger_manager->destroy(this->public.logger_manager);
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
	this->destroy = destroy;
	this->build_test_jobs = build_test_jobs;
	this->initialize = initialize;
	this->public.kill = (void (*) (daemon_t*,char*))kill_daemon;
	
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
	
	this->main_thread_id = pthread_self();
	
	/* setup signal handling */
	sigemptyset(&(this->signal_set));
	sigaddset(&(this->signal_set), SIGINT); 
	sigaddset(&(this->signal_set), SIGHUP); 
	sigaddset(&(this->signal_set), SIGTERM); 
	pthread_sigmask(SIG_BLOCK, &(this->signal_set), 0);
	
	return this;
}

/**
 * Main function, manages the daemon.
 */
int main(int argc, char *argv[])
{
	private_daemon_t *private_charon;
	
	/* allocation needs initialization, before any allocs are done */
	allocator_init();
	
	private_charon = daemon_create();
	charon = (daemon_t*)private_charon;
	
	private_charon->initialize(private_charon);
	
	private_charon->build_test_jobs(private_charon);
	
	private_charon->run(private_charon);
	
	private_charon->destroy(private_charon);
	
#ifdef LEAK_DETECTIVE
	report_memory_leaks(void);
#endif

	exit(0);
}

