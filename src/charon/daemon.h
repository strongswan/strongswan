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

typedef struct daemon_t daemon_t;

#include <credential_store.h>

#include <network/sender.h>
#include <network/receiver.h>
#include <network/socket.h>
#include <processing/scheduler.h>
#include <processing/thread_pool.h>
#include <processing/job_queue.h>
#include <processing/event_queue.h>
#include <kernel/kernel_interface.h>
#include <control/stroke_interface.h>
#include <bus/bus.h>
#include <bus/listeners/file_logger.h>
#include <bus/listeners/sys_logger.h>
#include <sa/ike_sa_manager.h>
#include <config/cfg_store.h>
#include <config/backends/local_backend.h>

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
       +------------+

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
 * packet in the sender. The sender thread waits for those packets and sends
 * them over the wire, via the socket. The receiver does exactly the opposite of
 * the sender. It waits on the socket, reads in packets an places them on the
 * job-queue for further processing by a thread from the pool.
 * There are even more threads, not drawn in the upper scheme. The stroke thread
 * is responsible for reading and processessing commands from another process. The
 * kernel interface thread handles communication from and to the kernel via a
 * netlink socket. It waits for kernel events and processes them appropriately.
 */

/**
 * @defgroup bus bus
 *
 * Signaling bus and its listeners.
 *
 * @ingroup charon
 */

/**
 * @defgroup config config
 *
 * Classes implementing configuration related things.
 *
 * @ingroup charon
 */

/**
 * @defgroup backends backends
 *
 * Classes implementing configuration backends.
 *
 * @ingroup config
 */

/**
 * @defgroup credentials credentials
 *
 * Trust chain verification and certificate store.
 *
 * @ingroup config
 */

/**
 * @defgroup control control
 *
 * Classes which control the daemon using IPC mechanisms.
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
 * @defgroup kernel kernel
 *
 * Classes to configure and query the kernel.
 *
 * @ingroup charon
 */

/**
 * @defgroup network network
 *
 * Classes for sending and receiving UDP packets over the network.
 *
 * @ingroup charon
 */

/**
 * @defgroup processing processing
 *
 * Queueing, scheduling and processing of jobs
 *
 * @ingroup charon
 */

/**
 * @defgroup jobs jobs
 *
 * Jobs to queue, schedule and process.
 *
 * @ingroup processing
 */

/**
 * @defgroup sa sa
 *
 * Security associations for IKE and IPSec, and its helper classes.
 *
 * @ingroup charon
 */

/**
 * @defgroup authenticators authenticators
 *
 * Authenticator classes to prove identity of a peer.
 *
 * @ingroup sa
 */

/**
 * @defgroup eap eap
 *
 * EAP module loader, interface and it's implementations.
 *
 * @ingroup authenticators
 */
 
/**
 * @defgroup tasks tasks
 *
 * Tasks process and build message payloads. They are used to create
 * and process multiple exchanges.
 *
 * @ingroup sa
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
 * Default directory for trusted Certification Authority certificates
 * 
 * @ingroup charon
 */
#define CA_CERTIFICATE_DIR IPSEC_D_DIR "/cacerts"

/**
 * Default directory for Authorization Authority certificates
 * 
 * @ingroup charon
 */
#define AA_CERTIFICATE_DIR IPSEC_D_DIR "/aacerts"

/**
 * Default directory for Attribute certificates
 * 
 * @ingroup charon
 */
#define ATTR_CERTIFICATE_DIR IPSEC_D_DIR "/acerts"

/**
 * Default directory for OCSP signing certificates
 * 
 * @ingroup charon
 */
#define OCSP_CERTIFICATE_DIR IPSEC_D_DIR "/ocspcerts"

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
	 * A connection_store_t instance.
	 */
	cfg_store_t *cfg_store;
	
	/**
	 * A backend for cfg_store using in-memory lists
	 */
	local_backend_t *local_backend;
	
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
	 * The signaling bus.
	 */
	bus_t *bus;
	
	/**
	 * A bus listener logging to stdout
	 */
	file_logger_t *outlog;
	
	/**
	 * A bus listener logging to syslog
	 */
	sys_logger_t *syslog;
	
	/**
	 * A bus listener logging most important events
	 */
	sys_logger_t *authlog;
	
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
