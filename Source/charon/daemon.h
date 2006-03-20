/**
 * @file daemon.h
 * 
 * @brief Interface of daemon_t.
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

#ifndef DAEMON_H_
#define DAEMON_H_

#include <threads/sender.h>
#include <threads/receiver.h>
#include <threads/scheduler.h>
#include <threads/kernel_interface.h>
#include <threads/thread_pool.h>
#include <threads/stroke.h>
#include <network/socket.h>
#include <sa/ike_sa_manager.h>
#include <queues/send_queue.h>
#include <queues/job_queue.h>
#include <queues/event_queue.h>
#include <utils/logger_manager.h>
#include <config/configuration.h>
#include <config/connection_store.h>
#include <config/policy_store.h>
#include <config/credential_store.h>

/**
 * Name of the daemon.
 */
#define DAEMON_NAME "charon"

/**
 * @brief Number of threads in the thread pool.
 * 
 * There are several other threads, this defines
 * only the number of threads in thread_pool_t.
 */
#define NUMBER_OF_WORKING_THREADS 4

/**
 * UDP Port on which the daemon will listen for incoming traffic.
 */
#define IKEV2_UDP_PORT 500

/**
 * PID file, in which charon stores its process id
 */
#define PID_FILE "/var/run/charon.pid"

/**
 * Output of log, use NULL for syslog
 */
#define LOG_OUTPUT NULL

/**
 * @brief Default loglevel for every logger context.
 * 
 * This is the maximum allowed level for ever context, the definiton
 * of the context may be less verbose.
 */
#define DEFAULT_LOGLEVEL CONTROL | ERROR | AUDIT


typedef struct daemon_t daemon_t;

/**
 * @brief Main class of daemon, contains some globals.
 */ 
struct daemon_t {
	/**
	 * A socket_t instance.
	 */
	socket_t *socket;
	
	/**
	 * A send_queue_t instance.
	 */
	send_queue_t *send_queue;
	
	/**
	 * A job_queue_t instance.
	 */
	job_queue_t *job_queue;
	
	/**
	 * A event_queue_t instance.
	 */
	event_queue_t *event_queue;
	
	/**
	 * A logger_manager_t instance.
	 */
	logger_manager_t *logger_manager;

	/**
	 * A ike_sa_manager_t instance.
	 */
	ike_sa_manager_t *ike_sa_manager;
	
	/**
	 * A configuration_t instance.
	 */
	configuration_t *configuration;
	
	/**
	 * A connection_store_t instance.
	 */
	connection_store_t *connections;
	
	/**
	 * A policy_store_t instance.
	 */
	policy_store_t *policies;
	
	/**
	 * A credential_store_t instance.
	 */
	credential_store_t *credentials;
	
	/**
	 * The Sender-Thread.
 	 */
	sender_t *sender;
	
	/**
	 * The Receiver-Thread.
	 */
	receiver_t *receiver;
	
	/**
	 * The Scheduler-Thread.
	 */
	scheduler_t *scheduler;
	
	/**
	 * The Thread pool managing the worker threads.
	 */
	thread_pool_t *thread_pool;
	
	/**
	 * Kernel Interface to communicate with kernel
	 */
	kernel_interface_t *kernel_interface;
	
	/**
	 * IPC interface, as whack in pluto
	 */
	stroke_t *stroke;
	
	/**
	 * @brief Shut down the daemon.
	 * 
	 * @param this		the daemon to kill
	 * @param reason	describtion why it will be killed
	 */
	void (*kill) (daemon_t *this, char *reason);
};

/**
 * The one and only instance of the daemon.
 */
extern daemon_t *charon;

#endif /*DAEMON_H_*/
