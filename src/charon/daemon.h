/**
 * @file daemon.h
 * 
 * @brief Interface of daemon_t.
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

#ifndef DAEMON_H_
#define DAEMON_H_

#include <threads/sender.h>
#include <threads/receiver.h>
#include <threads/scheduler.h>
#include <threads/kernel_interface.h>
#include <threads/thread_pool.h>
#include <threads/stroke_interface.h>
#include <network/socket.h>
#include <sa/ike_sa_manager.h>
#include <queues/send_queue.h>
#include <queues/job_queue.h>
#include <queues/event_queue.h>
#include <utils/logger_manager.h>
#include <config/configuration.h>
#include <config/connections/connection_store.h>
#include <config/policies/policy_store.h>
#include <config/credentials/credential_store.h>

/**
 * @defgroup charon charon
 *
 * @brief IKEv2 keying daemon.
 *
 * @section Architecture
 *
 * All IKEv2 stuff is handled in charon. It uses a newer and more flexible
 * architecture than pluto. Charon uses a thread-pool, which allows parallel
 * execution SA-management. Beside the thread-pool, there are some special purpose
 * threads which do their job for the common health of the daemon.
   @verbatim 
                         +------+
                         | E  Q |
                         | v  u |---+                   +------+  +------+
                         | e  e |   |                   |      |  | IKE- |
                         | n  u |  +-----------+        |      |--| SA   |
                         | t  e |  |           |        | I  M |  +------+
       +------------+    | -    |  | Scheduler |        | K  a |
       |  receiver  |    +------+  |           |        | E  n |  +------+
       +----+-------+              +-----------+        | -  a |  | IKE- |
            |      |     +------+   |                   | S  g |--| SA   |
    +-------+--+   +-----| J  Q |---+  +------------+   | A  e |  +------+
   -|  socket  |         | o  u |      |            |   | -  r |
    +-------+--+         | b  e |      |   Thread-  |   |      |
            |            | -  u |      |   Pool     |   |      |
       +----+-------+    |    e |------|            |---|      |
       |   sender   |    +------+      +------------+   +------+
       +----+-------+
            |            +------+
            |            | S  Q |
            |            | e  u |
            |            | n  e |
            +------------| d  u |
                         | -  e |
                         +--+---+
   @endverbatim
 * The thread-pool is the heart of the architecture. It processes jobs from a
 * (fully synchronized) job-queue. Mostly, a job is associated with a specific
 * IKE SA. These IKE SAs are synchronized, only one thread can work one an IKE SA.
 * This makes it unnecesary to use further synchronisation methods once a IKE SA
 * is checked out. The (rather complex) synchronization of IKE SAs is completely
 * done in the IKE SA manager.
 * The sceduler is responsible for event firing. It waits until a event in the
 * (fully synchronized) event-queue is ready for processing and pushes the event
 * down to the job-queue. A thread form the pool will pick it up as quick as
 * possible. Every thread can queue events or jobs. Furter, an event can place a
 * packet in the send-queue. The sender thread waits for those packets and sends
 * them over the wire, via the socket. The receiver does exactly the opposite of
 * the sender. It waits on the socket, reads in packets an places them on the
 * job-queue for further processing by a thread from the pool.
 * There are even more threads, not drawn in the upper scheme. The stroke thread
 * is responsible for reading and processessing commands from another process. The
 * kernel interface thread handles communication from and to the kernel via a
 * netlink socket. It waits for kernel events and processes them appropriately.
 */

/**
 * @defgroup config config
 *
 * Classes implementing configuration related things.
 *
 * @ingroup charon
 */

/**
 * @defgroup encoding encoding
 *
 * Classes used to encode and decode IKEv2 messages.
 *
 * @ingroup charon
 */

 /**
 * @defgroup payloads payloads
 *
 * Classes representing specific IKEv2 payloads.
 *
 * @ingroup encoding
 */

/**
 * @defgroup network network
 *
 * Classes for network relevant stuff.
 *
 * @ingroup charon
 */

/**
 * @defgroup queues queues
 *
 * Different kind of queues
 * (thread save lists).
 *
 * @ingroup charon
 */

/**
 * @defgroup jobs jobs
 *
 * Jobs used in job queue and event queue.
 *
 * @ingroup queues
 */

/**
 * @defgroup sa sa
 *
 * Security associations for IKE and IPSec,
 * and some helper classes.
 *
 * @ingroup charon
 */

/**
 * @defgroup transactions transactions
 *
 * Transactions represent a request/response
 * message exchange to implement the IKEv2
 * protocol exchange scenarios.
 *
 * @ingroup sa
 */

/**
 * @defgroup threads threads
 *
 * Threaded classes, which will do their job alone.
 *
 * @ingroup charon
 */

/**
 * Name of the daemon.
 * 
 * @ingroup charon
 */
#define DAEMON_NAME "charon"

/**
 * @brief Number of threads in the thread pool.
 * 
 * There are several other threads, this defines
 * only the number of threads in thread_pool_t.
 * 
 * @ingroup charon
 */
#define NUMBER_OF_WORKING_THREADS 4

/**
 * UDP Port on which the daemon will listen for incoming traffic.
 * 
 * @ingroup charon
 */
#define IKEV2_UDP_PORT 500

/**
 * UDP Port to which the daemon will float to if NAT is detected.
 *
 * @ingroup charon
 */
#define IKEV2_NATT_PORT 4500

/**
 * PID file, in which charon stores its process id
 * 
 * @ingroup charon
 */
#define PID_FILE IPSEC_PIDDIR "/charon.pid"

/**
 * Configuration directory
 * 
 * @ingroup charon
 */
#define CONFIG_DIR IPSEC_CONFDIR

/**
 * Directory of IPsec relevant files
 * 
 * @ingroup charon
 */
#define IPSEC_D_DIR CONFIG_DIR "/ipsec.d"

/**
 * Default directory for private keys
 * 
 * @ingroup charon
 */
#define PRIVATE_KEY_DIR IPSEC_D_DIR "/private"

/**
 * Default directory for end entity certificates
 * 
 * @ingroup charon
 */
#define CERTIFICATE_DIR IPSEC_D_DIR "/certs"

/**
 * Default directory for trusted CA certificates
 * 
 * @ingroup charon
 */
#define CA_CERTIFICATE_DIR IPSEC_D_DIR "/cacerts"

/**
 * Default directory for CRLs
 * 
 * @ingroup charon
 */
#define CRL_DIR IPSEC_D_DIR "/crls"

/**
 * Secrets files
 * 
 * @ingroup charon
 */
#define SECRETS_FILE CONFIG_DIR "/ipsec.secrets"


typedef struct daemon_t daemon_t;

/**
 * @brief Main class of daemon, contains some globals.
 * 
 * @ingroup charon
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
