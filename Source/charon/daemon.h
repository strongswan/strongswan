/**
 * @file daemon.h
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

#ifndef DAEMON_H_
#define DAEMON_H_



#include <threads/sender.h>
#include <threads/receiver.h>
#include <threads/scheduler.h>
#include <threads/thread_pool.h>
#include <sa/ike_sa_manager.h>
#include <queues/send_queue.h>
#include <queues/job_queue.h>
#include <network/socket.h>
#include <queues/event_queue.h>
#include <utils/logger_manager.h>
#include <config/configuration_manager.h>

/**
 * Name of the daemon
 */
#define DAEMON_NAME "charon"

/**
 * Number of threads in the thread pool
 * 
 * There are several other threads, this defines
 * only the number of threads in thread_pool_t.
 */
#define NUMBER_OF_WORKING_THREADS 4

/**
 * Port on which the daemon will 
 * listen for incoming traffic
 */
#define IKEV2_UDP_PORT 500

/**
 * Default loglevel to use. This is the
 * maximum allowed level for ever context, the definiton
 * of the context may be less verbose.
 */
#define DEFAULT_LOGLEVEL FULL

typedef struct daemon_t daemon_t;

/**
 * @brief Main class of daemon, contains some globals 
 */ 
struct daemon_t {
	/**
	 * socket_t instance
	 */
	socket_t *socket;
	/**
	 * send_queue_t instance
	 */
	send_queue_t *send_queue;
	/**
	 * job_queue_t instance
	 */
	job_queue_t *job_queue;
	/**
	 * event_queue_t instance
	 */
	event_queue_t *event_queue;
	/**
	 * logger_manager_t instance
	 */
	logger_manager_t *logger_manager;
	/**
	 * ike_sa_manager_t instance
	 */
	ike_sa_manager_t *ike_sa_manager;
	/**
	 * configuration_manager_t instance
	 */
	configuration_manager_t *configuration_manager;
	
	/**
	 * Sender-Thread
 	 */
	sender_t *sender;
	
	/**
	 * Receiver-Thread
	 */
	receiver_t *receiver;
	
	/**
	 * Scheduler-Thread
	 */
	scheduler_t *scheduler;
	
	/**
	 * Thread pool holding the worker threads
	 */
	thread_pool_t *thread_pool;
	
	/**
	 * @brief shut down the daemon
	 * 
	 * @param this		the daemon to kill
	 * @param reason	describition why it will be killed
	 */
	void (*kill) (daemon_t *this, char *reason);
};

/**
 * one and only instance of the daemon
 */
extern daemon_t *charon;

#endif /*DAEMON_H_*/
