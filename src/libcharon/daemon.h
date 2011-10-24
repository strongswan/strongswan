/*
 * Copyright (C) 2006-2010 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2006 Daniel Roethlisberger
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

/**
 * @defgroup libcharon libcharon
 *
 * @defgroup bus bus
 * @ingroup libcharon
 *
 * @defgroup listeners listeners
 * @ingroup bus
 *
 * @defgroup config config
 * @ingroup libcharon
 *
 * @defgroup control control
 * @ingroup libcharon
 *
 * @defgroup encoding encoding
 * @ingroup libcharon
 *
 * @defgroup payloads payloads
 * @ingroup encoding
 *
 * @defgroup ckernel kernel
 * @ingroup libcharon
 *
 * @defgroup network network
 * @ingroup libcharon
 *
 * @defgroup cplugins plugins
 * @ingroup libcharon
 *
 * @defgroup cprocessing processing
 * @ingroup libcharon
 *
 * @defgroup cjobs jobs
 * @ingroup cprocessing
 *
 * @defgroup sa sa
 * @ingroup libcharon
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
 * @addtogroup libcharon
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
 * The bus receives signals from the different threads and relays them to
 * interested listeners. Debugging signals, but also important state changes or
 * error messages are sent over the bus.
 * Its listeners are not only for logging, but also to track the state of an
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
#include <network/socket_manager.h>
#include <control/controller.h>
#include <bus/bus.h>
#include <bus/listeners/file_logger.h>
#include <bus/listeners/sys_logger.h>
#include <sa/ike_sa_manager.h>
#include <sa/trap_manager.h>
#include <sa/shunt_manager.h>
#include <config/backend_manager.h>
#include <sa/authenticators/eap/eap_manager.h>

#ifdef ME
#include <sa/connect_manager.h>
#include <sa/mediation_manager.h>
#endif /* ME */

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
 * Main class of daemon, contains some globals.
 */
struct daemon_t {

	/**
	 * Socket manager instance
	 */
	socket_manager_t *socket;

	/**
	 * A ike_sa_manager_t instance.
	 */
	ike_sa_manager_t *ike_sa_manager;

	/**
	 * Manager for triggering policies, called traps
	 */
	trap_manager_t *traps;

	/**
	 * Manager for shunt PASS|DROP policies
	 */
	shunt_manager_t *shunts;

	/**
	 * Manager for the different configuration backends.
	 */
	backend_manager_t *backends;

	/**
	 * The Sender-Thread.
	 */
	sender_t *sender;

	/**
	 * The Receiver-Thread.
	 */
	receiver_t *receiver;

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
	 * Controller to control the daemon
	 */
	controller_t *controller;

	/**
	 * EAP manager to maintain registered EAP methods
	 */
	eap_manager_t *eap;

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
	 * Do not drop a given capability after initialization.
	 *
	 * Some plugins might need additional capabilites. They tell the daemon
	 * during plugin initialization which one they need, the daemon won't
	 * drop these.
	 */
	void (*keep_cap)(daemon_t *this, u_int cap);

	/**
	 * Drop all capabilities of the current process.
	 *
	 * Drops all capabalities, excect those exlcuded using keep_cap().
	 * This should be called after the initialization of the daemon because
	 * some plugins require the process to keep additional capabilities.
	 *
	 * @return		TRUE if successful, FALSE otherwise
	 */
	bool (*drop_capabilities)(daemon_t *this);

	/**
	 * Initialize the daemon.
	 */
	bool (*initialize)(daemon_t *this);

	/**
	 * Starts the daemon, i.e. spawns the threads of the thread pool.
	 */
	void (*start)(daemon_t *this);

};

/**
 * The one and only instance of the daemon.
 *
 * Set between libcharon_init() and libcharon_deinit() calls.
 */
extern daemon_t *charon;

/**
 * Initialize libcharon and create the "charon" instance of daemon_t.
 *
 * This function initializes the bus, listeners can be registered before
 * calling initialize().
 *
 * @return		FALSE if integrity check failed
 */
bool libcharon_init();

/**
 * Deinitialize libcharon and destroy the "charon" instance of daemon_t.
 */
void libcharon_deinit();

#endif /** DAEMON_H_ @}*/
