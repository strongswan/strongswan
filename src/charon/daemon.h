/*
 * Copyright (C) 2006-2007 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005-2008 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup charon charon
 *
 * @defgroup bus bus
 * @ingroup charon
 * 
 * @defgroup listeners listeners
 * @ingroup bus
 *
 * @defgroup config config
 * @ingroup charon
 *
 * @defgroup attributes attributes
 * @ingroup config
 *
 * @defgroup control control
 * @ingroup charon
 *
 * @defgroup ccredentials credentials
 * @ingroup charon
 *
 * @defgroup sets sets
 * @ingroup ccredentials
 *
 * @defgroup encoding encoding
 * @ingroup charon
 *
 * @defgroup payloads payloads
 * @ingroup encoding
 *
 * @defgroup kernel kernel
 * @ingroup charon
 *
 * @defgroup network network
 * @ingroup charon
 *
 * @defgroup cplugins plugins
 * @ingroup charon
 *
 * @defgroup processing processing
 * @ingroup charon
 *
 * @defgroup jobs jobs
 * @ingroup processing
 *
 * @defgroup sa sa
 * @ingroup charon
 *
 * @defgroup authenticators authenticators
 * @ingroup sa
 *
 * @defgroup eap eap
 * @ingroup authenticators
 *
 * @defgroup tasks tasks
 * @ingroup sa
 *
 * @addtogroup charon
 * @{
 *
 * IKEv2 keying daemon.
 *
 * All IKEv2 stuff is handled in charon. It uses a newer and more flexible
 * architecture than pluto. Charon uses a thread-pool (called processor),
 * which allows parallel execution SA-management. All threads originate
 * from the processor. Work is delegated to the processor by queueing jobs
 * to it.
   @verbatim
   
      +---------------------------------+       +----------------------------+
      |           controller            |       |          config            |
      +---------------------------------+       +----------------------------+  
               |      |      |                           ^     ^    ^           
               V      V      V                           |     |    |           
                                                                                
       +----------+  +-----------+   +------+            +----------+    +----+
       | receiver |  |           |   |      |  +------+  | CHILD_SA |    | K  |
       +---+------+  | Scheduler |   | IKE- |  | IKE- |--+----------+    | e  |
           |         |           |   | SA   |--| SA   |  | CHILD_SA |    | r  |
    +------+---+     +-----------+   |      |  +------+  +----------+    | n  |
 <->|  socket  |           |         | Man- |                            | e  |
    +------+---+     +-----------+   | ager |  +------+  +----------+    | l  |
           |         |           |   |      |  | IKE- |--| CHILD_SA |    | -  |
       +---+------+  | Processor |---|      |--| SA   |  +----------+    | I  |
       |  sender  |  |           |   |      |  +------+                  | f  |    
       +----------+  +-----------+   +------+                            +----+
                                                                                
               |      |      |                        |      |      |           
               V      V      V                        V      V      V           
      +---------------------------------+       +----------------------------+  
      |               Bus               |       |         credentials        |  
      +---------------------------------+       +----------------------------+                                                              

   @endverbatim
 * The scheduler is responsible to execute timed events. Jobs may be queued to 
 * the scheduler to get executed at a defined time (e.g. rekeying). The 
 * scheduler does not execute the jobs itself, it queues them to the processor.
 * 
 * The IKE_SA manager managers all IKE_SA. It further handles the 
 * synchronization:
 * Each IKE_SA must be checked out strictly and checked in again after use. The 
 * manager guarantees that only one thread may check out a single IKE_SA. This 
 * allows us to write the (complex) IKE_SAs routines non-threadsave.
 * The IKE_SA contain the state and the logic of each IKE_SA and handle the 
 * messages.
 * 
 * The CHILD_SA contains state about a IPsec security association and manages
 * them. An IKE_SA may have multiple CHILD_SAs. Communication to the kernel 
 * takes place here through the kernel interface.
 * 
 * The kernel interface installs IPsec security associations, policies, routes
 * and virtual addresses. It further provides methods to enumerate interfaces 
 * and may notify the daemon about state changes at lower layers.
 * 
 * The bus receives signals from the different threads and relais them to interested 
 * listeners. Debugging signals, but also important state changes or error 
 * messages are sent over the bus. 
 * It's listeners are not only for logging, but also to track the state of an
 * IKE_SA.
 *
 * The controller, credential_manager, bus and backend_manager (config) are 
 * places where a plugin ca register itself to privide information or observe
 * and control the daemon.
 */

#ifndef DAEMON_H_
#define DAEMON_H_

typedef struct daemon_t daemon_t;

#include <network/sender.h>
#include <network/receiver.h>
#include <network/socket.h>
#include <processing/scheduler.h>
#include <processing/processor.h>
#include <kernel/kernel_interface.h>
#include <control/controller.h>
#include <bus/bus.h>
#include <bus/listeners/file_logger.h>
#include <bus/listeners/sys_logger.h>
#include <sa/ike_sa_manager.h>
#include <config/backend_manager.h>
#include <config/attributes/attribute_manager.h>
#include <credentials/credential_manager.h>
#include <sa/authenticators/eap/eap_manager.h>
#include <sa/authenticators/eap/sim_manager.h>

#ifdef ME
#include <sa/connect_manager.h>
#include <sa/mediation_manager.h>
#endif /* ME */

/**
 * Name of the daemon.
 */
#define DAEMON_NAME "charon"

/**
 * Number of threads in the thread pool, if not specified in config.
 */
#define DEFAULT_THREADS 16

/**
 * UDP Port on which the daemon will listen for incoming traffic.
 */
#define IKEV2_UDP_PORT 500

/**
 * UDP Port to which the daemon will float to if NAT is detected.
 */
#define IKEV2_NATT_PORT 4500

/**
 * PID file, in which charon stores its process id
 */
#define PID_FILE IPSEC_PIDDIR "/charon.pid"


/**
 * Main class of daemon, contains some globals.
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
	 * Manager for IKEv2 cfg payload attributes
	 */
	attribute_manager_t *attributes;
	
	/**
	 * Manager for the credential backends
	 */
	credential_manager_t *credentials;
	
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
	 * A list of installed file_logger_t's
	 */
	linked_list_t *file_loggers;
	
	/**
	 * A list of installed sys_logger_t's
	 */
	linked_list_t *sys_loggers;
	
	/**
	 * Kernel Interface to communicate with kernel
	 */
	kernel_interface_t *kernel_interface;
	
	/**
	 * Controller to control the daemon
	 */
	controller_t *controller;
	
	/**
	 * EAP manager to maintain registered EAP methods
	 */
	eap_manager_t *eap;
	
	/**
	 * SIM manager to maintain SIM cards/providers
	 */
	sim_manager_t *sim;
	
#ifdef ME
	/**
	 * Connect manager
	 */
	connect_manager_t *connect_manager;
	
	/**
	 * Mediation manager
	 */
	mediation_manager_t *mediation_manager;
#endif /* ME */
	
	/**
	 * User ID the daemon will user after initialization
	 */
	uid_t uid;

	/**
	 * Group ID the daemon will use after initialization
	 */
	gid_t gid;
	
	/** 
	 * The thread_id of main-thread.
	 */
	pthread_t main_thread_id;
	
	/**
	 * Do not drop a given capability after initialization.
	 *
	 * Some plugins might need additional capabilites. They tell the daemon
	 * during plugin initialization which one they need, the daemon won't
	 * drop these.
	 */
	void (*keep_cap)(daemon_t *this, u_int cap);
	
	/**
	 * Shut down the daemon.
	 * 
	 * @param reason		describtion why it will be killed
	 */
	void (*kill) (daemon_t *this, char *reason);
};

/**
 * The one and only instance of the daemon.
 */
extern daemon_t *charon;

#endif /** DAEMON_H_ @}*/
