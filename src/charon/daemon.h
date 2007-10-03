/**
 * @file daemon.h
 *
 * @brief Interface of daemon_t.
 *
 */

/*
 * Copyright (C) 2006-2007 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
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
#include <processing/processor.h>
#include <kernel/kernel_interface.h>
#include <control/interface_manager.h>
#include <bus/bus.h>
#include <bus/listeners/file_logger.h>
#include <bus/listeners/sys_logger.h>
#include <sa/ike_sa_manager.h>
#include <config/backend_manager.h>

#ifdef P2P
#include <sa/connect_manager.h>
#include <sa/mediation_manager.h>
#endif /* P2P */

/**
 * @defgroup charon charon
 *
 * @brief IKEv2 keying daemon.
 *
 * All IKEv2 stuff is handled in charon. It uses a newer and more flexible
 * architecture than pluto. Charon uses a thread-pool (called processor),
 * which allows parallel execution SA-management. All threads originate
 * from the processor. Work is delegated to the processor by queueing jobs
 * to it.
   @verbatim                                             
                          
      +--------+   +-------+   +--------+       +-----------+    +-----------+
      | Stroke |   |  XML  |   |  DBUS  |       |   Local   |    |   SQLite  |
      +--------+   +-------+   +--------+       +-----------+    +-----------+
          |            |           |                  |                |
      +---------------------------------+       +----------------------------+
      |             Interfaces          |       |          Backends          |
      +---------------------------------+       +----------------------------+  
                                                                              
                                                                                
       +------------+    +-----------+        +------+            +----------+
       |  receiver  |    |           |        |      |  +------+  | CHILD_SA |
       +----+-------+    | Scheduler |        | IKE- |  | IKE- |--+----------+
            |            |           |        | SA   |--| SA   |  | CHILD_SA |
    +-------+--+         +-----------+        |      |  +------+  +----------+
 <->|  socket  |               |              | Man- |
    +-------+--+         +-----------+        | ager |  +------+  +----------+
            |            |           |        |      |  | IKE- |--| CHILD_SA |
       +----+-------+    | Processor |--------|      |--| SA   |  +----------+
       |   sender   |    |           |        |      |  +------+                  
       +------------+    +-----------+        +------+                   
                                                                                 
                                                                                
      +---------------------------------+       +----------------------------+
      |               Bus               |       |      Kernel Interface      |
      +---------------------------------+       +----------------------------+                                                                 
             |                    |                           |
      +-------------+     +-------------+                     V
      | File-Logger |     |  Sys-Logger |                  //////
      +-------------+     +-------------+                       


   @endverbatim
 * The scheduler is responsible to execute timed events. Jobs may be queued to 
 * the scheduler to get executed at a defined time (e.g. rekeying). The scheduler
 * does not execute the jobs itself, it queues them to the processor.
 * 
 * The IKE_SA manager managers all IKE_SA. It further handles the synchronization:
 * Each IKE_SA must be checked out strictly and checked in again after use. The 
 * manager guarantees that only one thread may check out a single IKE_SA. This allows
 * us to write the (complex) IKE_SAs routines non-threadsave.
 * The IKE_SA contain the state and the logic of each IKE_SA and handle the messages.
 * 
 * The CHILD_SA contains state about a IPsec security association and manages them. 
 * An IKE_SA may have multiple CHILD_SAs. Communication to the kernel takes place
 * here through the kernel interface.
 * 
 * The kernel interface installs IPsec security associations, policies routes and 
 * virtual addresses. It further provides methods to enumerate interfaces and may notify
 * the daemon about state changes at lower layers.
 * 
 * The bus receives signals from the different threads and relais them to interested 
 * listeners. Debugging signals, but also important state changes or error messages are
 * sent over the bus. 
 * It's listeners are not only for logging, but also to track the state of an IKE_SA.
 * 
 * The interface manager loads pluggable controlling interfaces. These are written to control
 * the daemon from external inputs (e.g. initiate IKE_SA, close IKE_SA, ...). The interface
 * manager further provides a simple API to establish these tasks.
 * Backends are pluggable modules which provide configuration. They have to implement an API
 * which the daemon core uses to get configuration.
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
 * Handling of loadable control interface modules.
 *
 * @ingroup charon
 */

/**
 * @defgroup interfaces interfaces
 *
 * Classes which control the daemon using IPC mechanisms.
 *
 * @ingroup control
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
 * @ingroup charon
 */
#define WORKER_THREADS 16

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
	 * A ike_sa_manager_t instance.
	 */
	ike_sa_manager_t *ike_sa_manager;
	
	/**
	 * Manager for the different configuration backends.
	 */
	backend_manager_t *backends;
	
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
	 * Job processing using a thread pool.
	 */
	processor_t *processor;
	
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
	 * Interfaces for IPC
	 */
	interface_manager_t *interfaces;
	
#ifdef P2P
	/**
	 * Connect manager
	 */
	connect_manager_t *connect_manager;
	
	/**
	 * Mediation manager
	 */
	mediation_manager_t *mediation_manager;
#endif /* P2P */
	
	/**
	 * @brief Shut down the daemon.
	 * 
	 * @param this			the daemon to kill
	 * @param reason		describtion why it will be killed
	 */
	void (*kill) (daemon_t *this, char *reason);
};

/**
 * The one and only instance of the daemon.
 */
extern daemon_t *charon;

#endif /*DAEMON_H_*/
