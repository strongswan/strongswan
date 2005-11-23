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
#include <ike_sa_manager.h>
#include <sender.h>
#include <receiver.h>
#include <scheduler.h>
#include <thread_pool.h>
#include <network/socket.h>
#include <utils/allocator.h>
#include <utils/logger_manager.h>
#include <queues/event_queue.h>
#include <queues/job_queue.h>
#include <queues/send_queue.h>


/* function declaration (defined and described after main function) */

static status_t initialize_globals();
static void destroy_globals();
static status_t start_threads();
static void end_threads();
static void main_loop();
static void register_signals();
static void destroy_and_exit(int);

/** Global job-queue */
job_queue_t *global_job_queue = NULL;
/** Global event-queue */
event_queue_t *global_event_queue = NULL;
 /** Global send-queue */
send_queue_t *global_send_queue = NULL;
 /** Global socket */
socket_t *global_socket = NULL;
/** Global logger manager */
logger_manager_t *global_logger_manager = NULL;
/** Global ike_sa-manager */
ike_sa_manager_t *global_ike_sa_manager = NULL;
/** Global configuration-manager */
configuration_manager_t *global_configuration_manager = NULL;

/**
 * logger_t object assigned for daemon things
 */
static logger_t *logger = NULL;

/**
 * Sender-Thread
 */
static sender_t *sender_thread = NULL;
/**
 * Receiver-Thread
 */
static receiver_t *receiver_thread = NULL;
/**
 * Scheduler-Thread
 */
static scheduler_t *scheduler_thread = NULL;
/**
 * Thread pool holding the worker threads
 */
static thread_pool_t *thread_pool = NULL;

/**
 * Signal set used for signal handling
 */
sigset_t signal_set;


int main()
{
	/* set signal handler */
	register_signals();
	
	/* logger_manager is created first */
 	global_logger_manager = logger_manager_create(FULL);
	if (global_logger_manager == NULL)
 	{
		printf("could not create logger manager");
 		return -1;
 	}

 	/* a own logger for the daemon is created */
 	logger = global_logger_manager->create_logger(global_logger_manager,DAEMON,NULL);
 	if (logger == NULL)
 	{
		printf("could not create logger object");
 		destroy_globals();
 		return -1;
 	}
	
	/* initialize all global objects */
 	if (initialize_globals() != SUCCESS)
 	{
 		destroy_globals();
 		return -1;
 	}
 	
 	logger->log(logger,CONTROL,"start daemon %s", DAEMON_NAME); 	
 	/* now  its time to create all the different threads :-) */ 
	if (start_threads() != SUCCESS)
	{
		/* ugh, not good */
	 	logger->log(logger,CONTROL,"Fatal error: Needed Threads could not be started");		
	 	destroy_and_exit(-1);
	}
	
//	int i;
//	for(i = 0; i<1; i++)
//	{
//		initiate_ike_sa_job_t *initiate_job;
//		
//		initiate_job = initiate_ike_sa_job_create("pinflb30");
//		global_event_queue->add_relative(global_event_queue, (job_t*)initiate_job, i * 1000);
//		
//	}
 	
 	logger->log(logger,CONTROL|MORE,"going to wait for exit signal");
 	/* go and handle signals*/
 	main_loop();
 	
 	destroy_and_exit(0);
 	
 	/* never reached */
 	return -1;
}

/**
 * Main Loop.
 * Waits for registered signals and acts dependently
 */
static void main_loop()
{
	while(1)
	{
	   int signal_number;
       int error;

       error = sigwait(&signal_set, &signal_number);

       if(error)
       {
              /* do error code */
			  logger->log(logger,CONTROL,"Error %d when waiting for signal",error);
              return;
       }
       switch (signal_number)
       {
			case SIGHUP:
			{
				logger->log(logger,CONTROL,"Signal of type SIGHUP received. Do nothing");
				break;
			}
			case SIGINT:
			{
				logger->log(logger,CONTROL,"Signal of type SIGINT received. Exit main loop.");
				return;
			}
			case SIGTERM:
			{
				logger->log(logger,CONTROL,"Signal of type SIGTERM received. Exit main loop.");			
				return;
			}
			default:
			{
				logger->log(logger,CONTROL,"Unknown signal %d received. Do nothing",signal_number);
				break;
			}
		}
	}
}

/**
 * Registers signals SIGINT, SIGHUP and SIGTERM.
 * Signals are handled in main_loop()
 */
static void register_signals()
{
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT); 
    sigaddset(&signal_set, SIGHUP); 
    sigaddset(&signal_set, SIGTERM); 
    pthread_sigmask(SIG_BLOCK, &signal_set, 0);

}

/**
 * Initializes global objects
 * 
 * @return
 * 			- SUCCESS
 * 			- FAILED
 */
static status_t initialize_globals()
{
 	/* initialize global object */
 	global_socket = socket_create(IKEV2_UDP_PORT);
 	global_ike_sa_manager = ike_sa_manager_create();
 	global_job_queue = job_queue_create();
 	global_event_queue = event_queue_create();
 	global_send_queue = send_queue_create();
 	global_configuration_manager = configuration_manager_create();
 	
 	if (	(global_socket == NULL) ||
		(global_job_queue == NULL) ||
		(global_event_queue == NULL) ||
		(global_send_queue == NULL) ||
		(global_configuration_manager == NULL) ||
		(global_ike_sa_manager == NULL))
 	{
	 	return FAILED;
 	}
 	
 	return SUCCESS;
}

/**
 * Destroy global objects
 */
static void destroy_globals()
{
	if (global_ike_sa_manager != NULL)
	{
		global_job_queue->destroy(global_job_queue);
	}
	if (global_event_queue != NULL)
	{
		global_event_queue->destroy(global_event_queue);	
	}
	if (global_send_queue != NULL)
	{
		global_send_queue->destroy(global_send_queue);	
	}
	if (global_socket != NULL)
	{
		global_socket->destroy(global_socket);
	}
	if (global_ike_sa_manager != NULL)
	{
		global_ike_sa_manager->destroy(global_ike_sa_manager);
	}
	if (global_configuration_manager != NULL)
	{
		global_configuration_manager->destroy(global_configuration_manager);
	}
}

/**
 * Creates all needed Threads
 * 
 * @return
 * 			- SUCCESS
 * 			- FAILED
 */
static status_t start_threads()
{
	sender_thread = sender_create();
	if (sender_thread == NULL)
	{
		return FAILED;
	}
	scheduler_thread = scheduler_create();
	if (scheduler_thread == NULL)
	{
		return FAILED;
	}
	thread_pool = thread_pool_create(NUMBER_OF_WORKING_THREADS);	
	if (thread_pool == NULL)
	{
		return FAILED;
	}
	receiver_thread = receiver_create();
	if (receiver_thread == NULL)
	{
		return FAILED;
	}	

	return SUCCESS;
}


/**
 * Ends all Threads
 * 
 */
static void end_threads()
{
	if (receiver_thread != NULL)
	{
		receiver_thread->destroy(receiver_thread);
	}
	if (scheduler_thread != NULL)
	{
		scheduler_thread->destroy(scheduler_thread);	
	}
	if (sender_thread != NULL)
	{
		sender_thread->destroy(sender_thread);
	}
	if (thread_pool != NULL)
	{
		thread_pool->destroy(thread_pool);	
	}

}

/**
 * Destroys initialized objects, kills all threads and exits
 * 
 * @param exit_code Code to exit with
 */
static void destroy_and_exit(int exit_code)
{
 	logger->log(logger,CONTROL,"going to exit daemon"); 	

	end_threads();
	
	/* all globals can be destroyed now */
	destroy_globals();
	
	/* logger is destroyed */
 	logger->log(logger,CONTROL|MORE,"destroy logger");
 	logger->log(logger,CONTROL|MORE,"destroy logger_manager");
 	logger->log(logger,CONTROL|MORE,"------------------------------------");
	global_logger_manager->destroy_logger(global_logger_manager,logger);
	global_logger_manager->destroy(global_logger_manager);

#ifdef LEAK_DETECTIVE
	/* Leaks are reported in log file */
	report_memory_leaks(void);
#endif

	exit(exit_code);	
}
